import asyncio
import hashlib
import hmac
import logging
import os
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request

from app.routes.items.get_alert_service import get_alert_service
from app.services.alert_service import AlertService

# Load env
load_dotenv()

router = APIRouter()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
WEBHOOK_SECRET_BYTES = WEBHOOK_SECRET.encode() if WEBHOOK_SECRET else b""

# URL destino para reenviar alertas normalizadas
FORWARD_ALERTS_URL = os.getenv(
    "FORWARD_ALERTS_URL", "https://secu-bot.vercel.app/api/v1/alerts"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("webhook")

DEBUG = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------


def _to_bytes(x: Optional[bytes | str]) -> bytes:
    if x is None:
        return b""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    return str(x).encode()


def verify_signature(
    body: bytes,
    signature_header: Optional[str],
    secret_bytes: Optional[bytes | str] = None,
) -> bool:
    if not isinstance(body, (bytes, bytearray, memoryview)):
        try:
            body = str(body).encode()
        except Exception:
            body = b""

    if not signature_header:
        if DEBUG:
            logger.debug("verify_signature: missing signature header")
        return False

    if isinstance(signature_header, (bytes, bytearray)):
        try:
            signature_header = signature_header.decode("utf-8", errors="ignore")
        except Exception:
            signature_header = str(signature_header)

    signature_header = signature_header.strip()
    if "=" not in signature_header:
        if DEBUG:
            logger.debug(
                "verify_signature: signature header no '=': %r", signature_header
            )
        return False

    sha_name, signature = signature_header.split("=", 1)
    if sha_name.strip().lower() != "sha256":
        if DEBUG:
            logger.debug("verify_signature: unsupported digest %r", sha_name)
        return False

    signature = signature.strip().lower()
    secret = (
        _to_bytes(secret_bytes)
        if secret_bytes is not None
        else WEBHOOK_SECRET_BYTES or b""
    )

    try:
        mac = hmac.new(secret, msg=body, digestmod=hashlib.sha256)
        expected_hex = mac.hexdigest().lower()
        result = hmac.compare_digest(expected_hex, signature)
        if DEBUG:
            logger.debug("verify_signature: result=%s signature=%s", result, signature)
        return result
    except Exception as exc:
        logger.exception("verify_signature: unexpected error: %s", exc)
        return False


async def _send_normalized_alert(normalized_alert: dict, source: str) -> None:
    """
    Envía la alerta normalizada (ya mapeada por AlertService) al endpoint POST externo

    Args:
        normalized_alert: Alerta ya normalizada por los mappers del AlertService
        source: Origen de la alerta (dependabot, owasp_zap, trivy_sast, etc.)
    """
    try:
        # Construir el formato requerido para el POST
        alert_payload = {
            "signature": normalized_alert.get("signature", ""),
            "source_id": normalized_alert.get("source_id", ""),
            "severity": normalized_alert.get("severity", "UNKNOWN"),
            "component": normalized_alert.get("component", ""),
            "quality": normalized_alert.get("quality", "good"),
            "normalized_payload": normalized_alert.get("normalized_payload", {}),
            "alert_id": normalized_alert.get("alert_id", ""),
            "status": normalized_alert.get("status", "open"),
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                FORWARD_ALERTS_URL,
                json=alert_payload,
                headers={"Content-Type": "application/json", "X-Source": source},
            )

            if response.status_code in (200, 201, 202):
                logger.info(
                    "Successfully forwarded normalized alert to %s (alert_id=%s)",
                    FORWARD_ALERTS_URL,
                    alert_payload.get("alert_id"),
                )
            else:
                logger.warning(
                    "Forward alert returned status %s: %s",
                    response.status_code,
                    response.text,
                )
    except Exception as e:
        logger.exception(
            "Error forwarding normalized alert to %s: %s", FORWARD_ALERTS_URL, e
        )


async def _enqueue_upsert(
    alert_data: dict, service: AlertService, source: str = "dependabot"
) -> None:
    """
    Ejecuta la creación o actualización de alertas usando AlertService
    en un hilo separado y luego envía la alerta normalizada al endpoint externo.
    """
    try:
        normalized_alert = None

        # Procesar con AlertService y obtener la alerta normalizada
        if source == "dependabot":
            normalized_alert = await asyncio.to_thread(
                service.create_alert_from_dependabot, alert_data
            )
            logger.info(
                "Dependabot alert upsert completed for id=%s", alert_data.get("id")
            )
        elif source == "owasp_zap":
            normalized_alert = await asyncio.to_thread(
                service.create_alert_from_zap, alert_data
            )
            logger.info("OWASP ZAP alert upsert completed")
        elif source == "trivy_sast":
            normalized_alert = await asyncio.to_thread(
                service.create_alert_from_trivy, alert_data
            )
            logger.info("Trivy SAST alerts upsert completed")
        else:
            logger.warning("Unknown source: %s", source)
            return

        # Si el mapper devolvió una alerta normalizada, enviarla al endpoint externo
        if normalized_alert:
            await _send_normalized_alert(normalized_alert, source)  # type: ignore
        else:
            logger.warning(
                "No normalized alert returned from AlertService for source=%s", source
            )

    except Exception as e:
        logger.exception(
            "Error executing AlertService in background for id=%s: %s",
            alert_data.get("id"),
            e,
        )


# --------------------------------------------------------------------
# Webhook principal
# --------------------------------------------------------------------


@router.post("/webhook")
async def webhook(
    request: Request, alert_service: AlertService = Depends(get_alert_service)
):
    """
    Endpoint GitHub App webhooks (Dependabot, …)
    - Verifica X-Hub-Signature-256
    - Responde rápido a ping
    - Normaliza payload con AlertService mappers y dispara en background
    - Envía alertas normalizadas a endpoint externo
    """
    if not DEBUG and not WEBHOOK_SECRET:
        logger.error("WEBHOOK_SECRET not configured (and DEBUG is false).")
        raise HTTPException(status_code=500, detail="Server misconfiguration")

    body = await request.body()

    sig = request.headers.get("x-hub-signature-256", "")
    event = request.headers.get("x-github-event", "")
    delivery = request.headers.get("x-github-delivery", "")
    content_type = request.headers.get("content-type", "")

    logger.info(
        "Webhook received: event=%s delivery=%s content-type=%s",
        event,
        delivery,
        content_type,
    )

    if "application/json" not in content_type.lower():
        logger.warning("Unexpected content-type: %s", content_type)

    if not verify_signature(body, sig):
        logger.warning("Invalid signature for delivery %s (event=%s)", delivery, event)
        raise HTTPException(status_code=400, detail="Invalid signature")

    try:
        payload = await request.json()
    except Exception as e:
        logger.exception("Invalid JSON body for delivery %s: %s", delivery, e)
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Ping event
    if event == "ping" or (
        isinstance(payload, dict) and (payload.get("zen") or payload.get("hook_id"))
    ):
        logger.info("Ping received (delivery=%s). Responding pong.", delivery)
        return {"status": "pong"}

    source = "dependabot"  # Default

    if isinstance(payload, dict):
        # Si viene con campo "source" explícito
        payload_source = payload.get("source", "")

        if payload_source == "owasp_zap":
            source = "owasp_zap"
            payload = payload.get("payload", payload)  # Extraer el payload interno
        elif payload_source == "trivy_sast":
            source = "trivy_sast"
            payload = payload.get("payload", payload)  # Extraer el payload interno
        # Si es un evento de GitHub (Dependabot)
        elif event:
            source = "dependabot"

    logger.info("Processing alert from source: %s", source)

    try:
        asyncio.create_task(_enqueue_upsert(payload, alert_service, source=source))
    except Exception as e:
        logger.exception(
            "Error scheduling AlertService task (delivery=%s): %s", delivery, e
        )
        raise HTTPException(status_code=500, detail="Error scheduling background task")

    logger.info("Accepted alert (delivery=%s)", delivery)
    return {"status": "accepted"}
