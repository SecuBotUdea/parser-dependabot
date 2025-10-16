import hashlib
import hmac
import os
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
    # Asegúrate de que body es bytes
    if not isinstance(body, (bytes, bytearray)):
        # si te viene str, codifícalo (evitar en producción: garantizar bytes desde Request)
        body = str(body).encode()

    # Normalizar header
    if not signature_header:
        return False
    if isinstance(signature_header, (bytes, bytearray)):
        signature_header = signature_header.decode()
    signature_header = signature_header.strip()

    # Esperamos 'sha256=<hex>'
    if "=" not in signature_header:
        return False
    sha_name, signature = signature_header.split("=", 1)
    if sha_name.strip().lower() != "sha256":
        return False

    signature = signature.strip().lower()
    # Normalizar secret
    if secret_bytes is None:
        # importa o usa la variable global WEBHOOK_SECRET_BYTES definida en tu módulo
        try:
            secret = WEBHOOK_SECRET_BYTES  # definida arriba en tu módulo
        except NameError:
            secret = b""
    else:
        secret = _to_bytes(secret_bytes)

    # Calcular HMAC
    mac = hmac.new(secret, msg=body, digestmod=hashlib.sha256)
    expected_hex = mac.hexdigest().lower()

    # Comparación segura en tiempo constante
    return hmac.compare_digest(expected_hex, signature)


@router.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    # Leemos cuerpo y firma
    body = await request.body()
    sig = request.headers.get("x-hub-signature-256", "")

    # Verificación HMAC
    if not verify_signature(body, sig):
        # 400 para firma inválida (podría ser 401, pero 400 es aceptable para webhooks inválidos)
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Parseamos JSON (si no es json, devolverá 400)
    payload = await request.json()

    # Mapear/normalizar -> este puede lanzar ValidationError si no cumple schema
    normalized = map_dependabot_payload(payload)

    # Guardar en background y responder rápido
    background_tasks.add_task(upsert_alert, normalized)
    return {"status": "accepted"}
