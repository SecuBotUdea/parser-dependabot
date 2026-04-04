import asyncio
import logging
import os

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

    # Detectar fuente
    source = "dependabot"

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

    try:
        asyncio.create_task(
            _enqueue_upsert(payload.alert, alert_service, source=source)
        )
    except Exception as e:
        logger.exception(
            "Error scheduling AlertService task (delivery=%s): %s", delivery, e
        )
        raise HTTPException(status_code=500, detail="Error scheduling background task")

    logger.info("Accepted alert (delivery=%s)", delivery)
    return {"status": "accepted"}
