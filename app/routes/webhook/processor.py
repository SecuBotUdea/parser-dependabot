import asyncio
import logging
import os

import httpx
from dotenv import load_dotenv

from app.services.alert_service import AlertService

load_dotenv()

logger = logging.getLogger("webhook.processor")

FORWARD_ALERTS_URL = os.getenv(
    "FORWARD_ALERTS_URL", "https://secu-bot.vercel.app/api/v1/alerts"
)


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
            "external_references_score": normalized_alert.get("external_references_score"),
            "normalized_payload": normalized_alert.get("normalized_payload", {}),
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
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
        logger.error("Error forwarding normalized alert to %s: %s", FORWARD_ALERTS_URL, e)


async def _enqueue_upsert(
    alert_data: dict, service: AlertService, source: str = "dependabot"
) -> None:
    try:
        if source == "dependabot":
            logger.info("Processing Dependabot alert")
            normalized_alert = await asyncio.to_thread(
                service.create_alert_from_dependabot, alert_data
            )
            logger.info("Dependabot alert upsert completed for id=%s", alert_data.get("id"))
            if normalized_alert:
                await _send_normalized_alert(normalized_alert.model_dump(mode="json"), source)

        elif source == "owasp_zap":
            logger.info("Processing OWASP ZAP alert")
            normalized_alerts = await asyncio.to_thread(
                service.create_alert_from_zap, alert_data
            )
            logger.info("OWASP ZAP alerts upsert completed (%d alerts)", len(normalized_alerts))
            for alert in normalized_alerts:
                await _send_normalized_alert(alert.model_dump(mode="json"), source)

        elif source == "trivy_sast":
            logger.info("Processing Trivy SAST alert")
            normalized_alerts = await asyncio.to_thread(
                service.create_alert_from_trivy, alert_data
            )
            logger.info("Trivy SAST alerts upsert completed (%d alerts)", len(normalized_alerts))
            for alert in normalized_alerts:
                await _send_normalized_alert(alert.model_dump(mode="json"), source)

        else:
            logger.warning("Unknown source: %s", source)

    except Exception as e:
        logger.error(
            "Error executing AlertService in background for id=%s: %s",
            alert_data.get("id"),
            e,
        )
