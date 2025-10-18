import hashlib
import hmac
import os
import logging
from typing import Optional

from dotenv import load_dotenv
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from .db import upsert_alert
from .mapper import map_dependabot_payload

# Cargar variables de entorno
load_dotenv()

router = APIRouter()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET") or ""
WEBHOOK_SECRET_BYTES = WEBHOOK_SECRET.encode()

# Configurar logger básico
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("webhook")

DEBUG = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")


def _to_bytes(x: Optional[bytes | str]) -> bytes:
    if x is None:
        return b""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode()


def verify_signature(
    body: bytes, signature_header: str, secret_bytes: Optional[bytes | str] = None
) -> bool:
    """
    Verifica 'X-Hub-Signature-256' (formato "sha256=<hex>") contra body.
    - normaliza tipos y espacios
    - acepta secret_bytes como bytes o str (si no se pasa, usa WEBHOOK_SECRET_BYTES)
    """
    if not isinstance(body, (bytes, bytearray)):
        body = str(body).encode()

    if not signature_header:
        return False
    if isinstance(signature_header, (bytes, bytearray)):
        signature_header = signature_header.decode()
    signature_header = signature_header.strip()

    if "=" not in signature_header:
        return False
    sha_name, signature = signature_header.split("=", 1)
    if sha_name.strip().lower() != "sha256":
        return False

    signature = signature.strip().lower()

    if secret_bytes is None:
        try:
            secret = WEBHOOK_SECRET_BYTES
        except NameError:
            secret = b""
    else:
        secret = _to_bytes(secret_bytes)

    mac = hmac.new(secret, msg=body, digestmod=hashlib.sha256)
    expected_hex = mac.hexdigest().lower()

    return hmac.compare_digest(expected_hex, signature)


@router.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Endpoint que recibe eventos de GitHub App (Dependabot, etc.)
    - Verifica firma HMAC con X-Hub-Signature-256
    - Responde rápido a 'ping' y evita fallos en eventos desconocidos
    - Encola procesamiento de alertas en background
    """
    body = await request.body()
    sig = request.headers.get("x-hub-signature-256", "")
    event = request.headers.get("x-github-event", "")
    delivery = request.headers.get("x-github-delivery", "")
    encoded_secret = request.headers.get("x-github-encoded-secret")

    logger.info(
        "Webhook recibido: event=%s delivery=%s encoded_secret=%s",
        event,
        delivery,
        bool(encoded_secret),
    )

    # --- Verificar firma HMAC ---
    if not verify_signature(body, sig):
        logger.warning("Firma inválida para delivery %s (event=%s)", delivery, event)

        # Solo para debug opcional (no activar en prod)
        if DEBUG:
            try:
                import hashlib, hmac
                secret = (os.getenv("WEBHOOK_SECRET") or "").encode()
                mac = hmac.new(secret, msg=body, digestmod=hashlib.sha256)
                expected = "sha256=" + mac.hexdigest()
                logger.debug("DEBUG firma recibida=%s esperada=%s", sig, expected)
            except Exception as e:
                logger.exception("DEBUG: fallo al recalcular firma: %s", e)

        raise HTTPException(status_code=400, detail="Invalid signature")

    # --- Parsear JSON ---
    payload = await request.json()

    # --- Manejar ping (evento de prueba) ---
    if event == "ping" or payload.get("zen") or payload.get("hook_id"):
        logger.info("Ping recibido (delivery=%s). Respondiendo pong.", delivery)
        return {"status": "pong"}

    # --- Procesar payload normal ---
    try:
        normalized = map_dependabot_payload(payload)
    except Exception as e:
        logger.exception("Error al mapear payload (delivery=%s): %s", delivery, e)
        raise HTTPException(status_code=400, detail="Invalid payload format")

    try:
        background_tasks.add_task(upsert_alert, normalized)
    except Exception as e:
        logger.exception("Error al encolar tarea (delivery=%s): %s", delivery, e)
        raise HTTPException(status_code=500, detail="Internal error")

    return {"status": "accepted"}
