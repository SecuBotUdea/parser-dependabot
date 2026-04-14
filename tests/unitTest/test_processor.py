import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.alert_model import Alert as AlertModel
from app.models.alert_model import AlertSeverity, AlertSource, AlertStatus
from app.routes.webhook.processor import _enqueue_upsert, _send_normalized_alert


@pytest.fixture
def sample_alert_model():
    """AlertModel mínimo válido para usar como fixture en tests del processor."""
    return AlertModel(
        alert_id="dependabot-test-repo-42",
        source_type=AlertSource.dependabot,
        source_id="42",
        title="Test vulnerability in requests",
        severity=AlertSeverity.high,
        status=AlertStatus.open,
        component="requests",
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


def test_send_normalized_alert_silently_fails_with_alert_model(sample_alert_model):
    """
    Bug T-P2: _send_normalized_alert recibe AlertModel en lugar de dict.

    Cuando _enqueue_upsert llama a _send_normalized_alert(normalized_alert, source),
    normalized_alert es un AlertModel (objeto Pydantic), no un dict.
    La función intenta hacer normalized_alert.get("signature", "") pero AlertModel
    no tiene método .get() → AttributeError.

    El except interno captura el error silenciosamente: la función retorna sin
    hacer el POST, la alerta nunca llega a secu-bot y no hay ninguna señal
    externa de que algo falló.

    Este test verifica que el HTTP POST nunca se ejecuta cuando se recibe
    un AlertModel, documentando el bug antes de corregirlo.
    """
    with patch("app.routes.webhook.processor.httpx.AsyncClient") as mock_client:
        mock_post = AsyncMock()
        mock_instance = AsyncMock()
        mock_instance.post = mock_post
        mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)

        # La función no debe lanzar excepción hacia afuera — la captura internamente
        asyncio.run(_send_normalized_alert(sample_alert_model, "dependabot"))

        # El POST nunca se ejecuta porque la función falla antes de construir
        # el payload, al llamar .get() sobre un objeto AlertModel
        mock_post.assert_not_called()


def test_enqueue_upsert_with_none_alert_data_raises_attribute_error():
    """
    Bug T-P1: _enqueue_upsert recibe alert_data=None y falla dos veces.

    Primera falla: el servicio intenta procesar None como si fuera un dict
    (el mapper llama a None.get(...)) → se lanza una excepción que el bloque
    except de _enqueue_upsert captura correctamente.

    Segunda falla: dentro del except, el logger intenta hacer alert_data.get("id")
    para incluir el ID en el mensaje de error. Como alert_data es None, esto lanza
    un AttributeError que esta vez NO está atrapado → propaga hacia afuera.

    Resultado: el background task explota sin dejar ningún log útil. El error
    original (None en lugar de dict) se pierde completamente.

    El test simula el escenario usando un servicio mock que lanza una excepción
    controlada, replicando lo que haría el mapper real al recibir None.
    """
    mock_service = MagicMock()
    mock_service.create_alert_from_dependabot.side_effect = AttributeError(
        "simulated: NoneType has no attribute 'get'"
    )

    with pytest.raises(AttributeError):
        asyncio.run(_enqueue_upsert(None, mock_service, source="dependabot"))
