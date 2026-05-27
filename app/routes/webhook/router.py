import logging
import os
import uuid
from datetime import datetime

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, Header, HTTPException, Request
import httpx

from app.models.alert_model import AlertStatus
from app.routes.items.get_alert_service import get_alert_service
from app.services.alert_service import AlertService

from .processor import (
    _enqueue_upsert,
    _parse_github_coords,
    _send_normalized_alert,
    _watchlist,
    trigger_analyzer,
)
from .security import WEBHOOK_SECRET, verify_signature

load_dotenv()

router = APIRouter()
logger = logging.getLogger("webhook.router")

DEBUG = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def _build_github_repo(alert_id: str) -> str:
    """
    alert_id format: {source}-{owner}-{repo}-{number}
    ej: "dependabot-pangoaguirre-learndependabot-12"
    Retorna "owner/repo", ej: "pangoaguirre/learndependabot"
    """
    parts = alert_id.split("-")
    # quita source (primero) y number (último)
    owner_repo = parts[1:-1]
    # jug-eared usa "owner-repo" pero GitHub API necesita "owner/repo"
    if len(owner_repo) >= 2:
        return f"{owner_repo[0]}/{'-'.join(owner_repo[1:])}"
    return "-".join(owner_repo)


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
        logger.info(f"[{alert_id}] Payload: {payload}")
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
                alert_data = payload.get("payload", payload)
            elif payload_source == "trivy_sast":
                source = "trivy_sast"
                alert_data = payload.get("payload", payload)
            elif event:
                source = "dependabot"
                alert_data = payload.get("alert", payload)

        logger.info("Processing alert from source: %s", source)
    except Exception as e:
        logger.error(f"[{alert_id}] ERROR detecting source: {e}")
        raise HTTPException(status_code=400, detail="Error detecting alert source")

    try:
        await _enqueue_upsert(alert_data, alert_service, source=source)
    except Exception as e:
        logger.error(f"[{alert_id}] ERROR scheduling AlertService task: {e}")
        raise HTTPException(status_code=500, detail="Error scheduling background task")

    logger.info(f"[{alert_id}] Accepted alert (delivery=%s)", delivery)
    return {"status": "accepted"}


@router.post("/verify/{alert_id}")
async def verify_alert(
    alert_id: str,
    alert_service: AlertService = Depends(get_alert_service),
    x_github_token: str = Header(..., description="GitHub token provided by jug-eared"),
):
    alert = alert_service.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    owner, repo, source = _parse_github_coords(alert_id)
    github_repo = f"{owner}/{repo}"

    try:
        github_state = await trigger_analyzer(source, alert_id, x_github_token, github_repo)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (httpx.TimeoutException, httpx.RequestError):
        raise HTTPException(status_code=502, detail="Could not reach GitHub API")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    # Dependabot: estado resuelto directamente desde GitHub API
    if source == "dependabot" and github_state:
        STATUS_MAP = {
            "open": AlertStatus.open,
            "fixed": AlertStatus.fixed,
            "dismissed": AlertStatus.dismissed,
        }
        alert.status = STATUS_MAP.get(github_state, AlertStatus.unknown)
        await _send_normalized_alert(alert.model_dump(mode="json"), source)
        return {"status": "resolved", "alert_id": alert_id, "github_state": github_state}

    # ZAP y Trivy: esperar webhook del workflow
    _watchlist[alert_id] = datetime.utcnow()
    return {"status": "accepted", "alert_id": alert_id}