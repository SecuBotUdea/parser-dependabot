import asyncio
import logging
import os
from datetime import datetime
from typing import Optional

import httpx
from dotenv import load_dotenv

from app.models.alert_model import Alert, AlertStatus
from app.services.alert_service import AlertService

_watchlist: dict[str, datetime] = {}

load_dotenv()

logger = logging.getLogger("webhook.processor")


def _get_forward_alerts_url() -> str:
    url = os.getenv("FORWARD_ALERTS_URL")
    if not url:
        raise RuntimeError("FORWARD_ALERTS_URL no configurado en .env")
    return url


def _get_forward_status_url() -> str:
    url = os.getenv("FORWARD_STATUS_URL")
    if not url:
        raise RuntimeError("FORWARD_STATUS_URL no configurado en .env")
    return url


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
                _get_forward_alerts_url(),
                json=alert_payload,
                headers={"Content-Type": "application/json", "X-Source": source},
            )
            if response.status_code in (200, 201, 202):
                logger.info(
                    "Successfully forwarded alert to %s (alert_id=%s)",
                    _get_forward_alerts_url(),
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
            "Error forwarding normalized alert to %s: %s", _get_forward_alerts_url(), e
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
            await _handle_status_change(
                normalized_alert, previous_status, source, service
            )

        elif source == "owasp_zap":
            logger.info("Processing OWASP ZAP alert")
            results = await asyncio.to_thread(service.create_alert_from_zap, alert_data)
            for normalized_alert, previous_status in results:
                await _handle_status_change(
                    normalized_alert, previous_status, source, service
                )

        elif source == "trivy_sast":
            logger.info("Processing Trivy SAST alert")
            results = await asyncio.to_thread(
                service.create_alert_from_trivy, alert_data
            )
            for normalized_alert, previous_status in results:
                await _handle_status_change(
                    normalized_alert, previous_status, source, service
                )

        else:
            logger.warning("Unknown source: %s", source)

    except Exception as e:
        logger.error(
            "Error executing AlertService in background for id=%s: %s",
            alert_data.get("id"),
            e,
        )


async def _handle_status_change(
    alert: Alert, previous_status: Optional[str], source: str, service: AlertService
) -> None:
    await _send_normalized_alert(alert.model_dump(mode="json"), source)

    if alert.alert_id in _watchlist:
        owner, repo, alert_source = _parse_github_coords(alert.alert_id)
        existing_alerts = await asyncio.to_thread(
            service.get_alerts_by_github_coords, owner, repo, alert_source
        )
        found = any(a.alert_id == alert.alert_id for a in existing_alerts)

        if found:
            alert.status = AlertStatus.open
            await _send_normalized_alert(alert.model_dump(mode="json"), source)
            _watchlist.pop(alert.alert_id, None)
        else:

            async def _delayed_fixed():
                await asyncio.sleep(int(os.getenv("RESCAN_WAIT_SECONDS", "60")))
                alert.status = AlertStatus.fixed
                await _send_normalized_alert(alert.model_dump(mode="json"), source)
                _watchlist.pop(alert.alert_id, None)

            asyncio.create_task(_delayed_fixed())


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


def _parse_github_coords(alert_id: str) -> tuple[str, str, str]:
    parts = alert_id.split("-")
    # formato: {source}-{owner}-{repo}-{number}
    source = parts[0]
    owner = parts[1]
    repo = "-".join(parts[2:-1])
    return owner, repo, source
