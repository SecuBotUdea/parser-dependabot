import asyncio
import logging
import os
import uuid

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request

from app.routes.items.get_alert_service import get_alert_service
from app.services.alert_service import AlertService

from .processor import _enqueue_upsert
from .security import WEBHOOK_SECRET, verify_signature

load_dotenv()

router = APIRouter()
logger = logging.getLogger("webhook.router")

DEBUG = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


@router.post("/webhook")
async def webhook(
    request: Request, alert_service: AlertService = Depends(get_alert_service)
):
    """
    Endpoint GitHub App webhooks (Dependabot, OWASP ZAP, Trivy SAST).
    - Verifica X-Hub-Signature-256
    - Responde rápido a ping
    - Despacha procesamiento en background
    """
    alert_id = str(uuid.uuid4())
    logger.info(f"[{alert_id}] RECIBIDA")

    if not DEBUG and not WEBHOOK_SECRET:
        logger.error("WEBHOOK_SECRET not configured (and DEBUG is false).")
        raise HTTPException(status_code=500, detail="Server misconfiguration")

    try:
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
    except Exception as e:
        logger.error(f"[{alert_id}] ERROR reading request: {e}")
        raise HTTPException(status_code=400, detail="Invalid request")

    if "application/json" not in content_type.lower():
        logger.warning("Unexpected content-type: %s", content_type)

    if not verify_signature(body, sig):
        logger.warning("Invalid signature for delivery %s (event=%s)", delivery, event)
        raise HTTPException(status_code=400, detail="Invalid signature")

    try:
        payload = await request.json()
        logger.info(f"[{alert_id}] payload: {payload}")
    except Exception as e:
        logger.error(f"[{alert_id}] ERROR: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Ping event
    if event == "ping" or (
        isinstance(payload, dict) and (payload.get("zen") or payload.get("hook_id"))
    ):
        logger.info("Ping received (delivery=%s). Responding pong.", delivery)
        return {"status": "pong"}

    # Detectar fuente
    source = "dependabot"

    try:
        if isinstance(payload, dict):
            payload_source = payload.get("source", "")

            if payload_source == "owasp_zap":
                source = "owasp_zap"
                payload = payload.get("payload", payload)
            elif payload_source == "trivy_sast":
                source = "trivy_sast"
                payload = payload.get("payload", payload)
            elif event:
                source = "dependabot"

        logger.info("Processing alert from source: %s", source)
    except Exception as e:
        logger.error(f"[{alert_id}] ERROR detecting source: {e}")
        raise HTTPException(status_code=400, detail="Error detecting alert source")

    try:
        asyncio.create_task(
            _enqueue_upsert(payload.get("alert"), alert_service, source=source)
        )
        logger.info(
            f"[{alert_id}] Scheduled AlertService task for delivery {delivery} (event={event})"
        )
    except Exception as e:
        logger.error(f"[{alert_id}] ERROR scheduling AlertService task: {e}")
        raise HTTPException(status_code=500, detail="Error scheduling background task")

    logger.info(f"[{alert_id}] Accepted alert (delivery=%s)", delivery)
    return {"status": "accepted"}
