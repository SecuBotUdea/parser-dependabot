import asyncio
import logging
import os
from typing import Optional

import httpx
from dotenv import load_dotenv

from app.models import alert_model
from app.services.alert_service import AlertService

load_dotenv()

logger = logging.getLogger("webhook.processor")

FORWARD_ALERTS_URL = os.getenv("FORWARD_ALERTS_URL")
if not FORWARD_ALERTS_URL:
    raise RuntimeError("FORWARD_ALERTS_URL no configurado")

FORWARD_STATUS_URL = os.getenv("FORWARD_STATUS_URL")
if not FORWARD_STATUS_URL:
    raise RuntimeError("FORWARD_STATUS_URL no configurado")


async def _send_normalized_alert(normalized_alert: dict, source: str) -> None:
    try:
        alert_payload = {
            "alert_id": normalized_alert.get("alert_id", ""),
            "source_type": normalized_alert.get("source_type", ""),
            "source_id": normalized_alert.get("source_id", ""),
            "title": normalized_alert.get("title", ""),
            "severity": normalized_alert.get("severity", "unknown"),
            "status": normalized_alert.get("status", "unknown"),
            "component": normalized_alert.get("component", ""),
            "location": normalized_alert.get("location"),
            "external_references_score": normalized_alert.get(
                "external_references_score"
            ),
            "normalized_payload": normalized_alert.get("normalized_payload", {}),
        }
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.post(
                FORWARD_ALERTS_URL,
                json=alert_payload,
                headers={"Content-Type": "application/json", "X-Source": source},
            )
            if response.status_code in (200, 201, 202):
                logger.info(
                    "Successfully forwarded alert to %s (alert_id=%s)",
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
        logger.error(
            "Error forwarding normalized alert to %s: %s", FORWARD_ALERTS_URL, e
        )


async def _enqueue_upsert(
    alert_data: dict, service: AlertService, source: str = "dependabot"
) -> None:
    try:
        if source == "dependabot":
            logger.info("Processing Dependabot alert")
            normalized_alert, previous_status = await asyncio.to_thread(
                service.create_alert_from_dependabot, alert_data
            )
            await _handle_status_change(normalized_alert, previous_status, source)

        elif source == "owasp_zap":
            logger.info("Processing OWASP ZAP alert")
            results = await asyncio.to_thread(service.create_alert_from_zap, alert_data)
            for normalized_alert, previous_status in results:
                await _handle_status_change(normalized_alert, previous_status, source)

        elif source == "trivy_sast":
            logger.info("Processing Trivy SAST alert")
            results = await asyncio.to_thread(
                service.create_alert_from_trivy, alert_data
            )
            for normalized_alert, previous_status in results:
                await _handle_status_change(normalized_alert, previous_status, source)

        else:
            logger.warning("Unknown source: %s", source)

    except Exception as e:
        logger.error(
            "Error executing AlertService in background for id=%s: %s",
            alert_data.get("id"),
            e,
        )


async def _handle_status_change(
    alert: alert_model, previous_status: Optional[str], source: str
) -> None:
    await _send_normalized_alert(alert.model_dump(mode="json"), source)

    if previous_status and previous_status != alert.status.value:
        logger.info(
            "Status changed for alert_id=%s: %s → %s",
            alert.alert_id,
            previous_status,
            alert.status.value,
        )
        await _notify_secu_bot_status_change(alert, previous_status)


async def trigger_analyzer(
    source_type: str, alert_id: str, github_token: str, github_repo: str
) -> None:
    if not github_token or not github_repo:
        logger.error(
            "github_token or github_repo not provided for alert_id=%s", alert_id
        )
        return

    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
    }

    async with httpx.AsyncClient() as client:
        if source_type == "zap":
            await client.post(
                f"https://api.github.com/repos/{github_repo}/actions/workflows/Owasp_Zap.yml/dispatches",
                json={"ref": "main"},
                headers=headers,
            )
        elif source_type == "trivy":
            await client.post(
                f"https://api.github.com/repos/{github_repo}/actions/workflows/Trivy.yml/dispatches",
                json={"ref": "main"},
                headers=headers,
            )
        elif source_type == "dependabot":
            await client.put(
                f"https://api.github.com/repos/{github_repo}/vulnerability-alerts",
                headers=headers,
            )

    logger.info(
        "Triggered analyzer for source=%s alert_id=%s repo=%s",
        source_type,
        alert_id,
        github_repo,
    )


async def _notify_secu_bot_status_change(
    alert: alert_model, previous_status: str
) -> None:
    try:
        payload = {
            "alert_id": alert.alert_id,
            "source_type": alert.source_type.value,
            "previous_status": previous_status,
            "current_status": alert.status.value,
            "component": alert.component,
            "severity": alert.severity.value,
        }
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.post(
                FORWARD_STATUS_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            logger.info(
                "Status change notified for alert_id=%s: %s → %s (HTTP %s)",
                alert.alert_id,
                previous_status,
                alert.status.value,
                response.status_code,
            )
    except Exception as e:
        logger.error(
            "Error notifying status change for alert_id=%s: %s", alert.alert_id, e
        )
