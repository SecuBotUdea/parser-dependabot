# secubot/webhook.py
import asyncio
import hashlib
import hmac
import logging
import os
from typing import Optional

from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Request

from app.services.alert_service import create_alert_from_dependabot

# Load env
load_dotenv()

router = APIRouter()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
WEBHOOK_SECRET_BYTES = WEBHOOK_SECRET.encode() if WEBHOOK_SECRET else b""

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("webhook")

DEBUG = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")


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


async def _enqueue_upsert(alert_obj: dict) -> None:
    """
    Ejecuta upsert_alert en un hilo separado para evitar bloquear el event loop.
    También captura excepciones y las loggea.
    """
    try:
        # asyncio.to_thread ejecuta la función bloqueante en un hilo del pool del interprete
        await asyncio.to_thread(create_alert_from_dependabot, alert_obj)
        logger.info("upsert_alert completed for id=%s", alert_obj.get("id"))
    except Exception as e:
        logger.exception(
            "Error executing upsert_alert in background for id=%s: %s",
            alert_obj.get("id"),
            e,
        )


@router.post("/webhook")
async def webhook(request: Request):
    """
    Endpoint GitHub App webhooks (Dependabot, …)
    - Verifica X-Hub-Signature-256
    - Responde rápido a ping
    - Normaliza payload y dispara upsert_alert en background sin bloquear el loop
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
        if DEBUG:
            try:
                secret_sample = (
                    (os.getenv("WEBHOOK_SECRET") or "")[:8] + "..."
                    if os.getenv("WEBHOOK_SECRET")
                    else "<empty>"
                )
                hmac.new(
                    (os.getenv("WEBHOOK_SECRET") or "").encode(),
                    msg=body,
                    digestmod=hashlib.sha256,
                )
                logger.debug(
                    "DEBUG signature received=%s expected=sha256=... secret_sample=%s",
                    sig,
                    secret_sample,
                )
            except Exception:
                logger.debug("DEBUG: could not recompute expected signature")
        raise HTTPException(status_code=400, detail="Invalid signature")

    try:
        payload = await request.json()
    except Exception as e:
        logger.exception("Invalid JSON body for delivery %s: %s", delivery, e)
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # ping handling
    if event == "ping" or (
        isinstance(payload, dict) and (payload.get("zen") or payload.get("hook_id"))
    ):
        logger.info("Ping received (delivery=%s). Responding pong.", delivery)
        return {"status": "pong"}

    # map payload
    try:
        normalized = create_alert_from_dependabot(payload)
    except Exception as e:
        logger.exception("Error mapping payload (delivery=%s): %s", delivery, e)
        raise HTTPException(status_code=400, detail="Invalid payload format")
    
    logger.info("Accepted alert (delivery=%s id=%s)", delivery, normalized.get("id"))
    return {"status": "accepted"}
