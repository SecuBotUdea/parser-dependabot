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
    """
    Envía la alerta normalizada al endpoint POST externo.
    """
    try:
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
    Procesa la alerta con AlertService según la fuente y reenvía
    la alerta normalizada al endpoint externo.
    """
    try:
        normalized_alert = None

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
