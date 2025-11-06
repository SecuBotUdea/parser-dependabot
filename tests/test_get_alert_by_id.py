from unittest.mock import MagicMock, patch

from app.routes.get_alert_by_id import get_alert_by_id


@patch("app.routes.get_alert_by_id.get_alert_service")
def test_get_alert_by_id_found(mock_get_alert_service):
    """Debe devolver el alert cuando existe."""
    # Mock del servicio
    mock_service = MagicMock()
    mock_service.get_alert.return_value = {
        "id": "abc123",
        "name": "Test Alert",
        "severity": "high",
    }
    mock_get_alert_service.return_value = mock_service

    result = get_alert_by_id("abc123")

    # Debe devolver el alert directamente
    assert result == {
        "id": "abc123",
        "name": "Test Alert",
        "severity": "high",
    }

    mock_service.get_alert.assert_called_once_with("abc123")


@patch("app.routes.get_alert_by_id.get_alert_service")
def test_get_alert_by_id_not_found(mock_get_alert_service):
    """Debe devolver 404 si el alert no existe."""
    mock_service = MagicMock()
    mock_service.get_alert.return_value = None
    mock_get_alert_service.return_value = mock_service

    result = get_alert_by_id("not-found-id")

    # Debe devolver el mensaje de error y el status 404
    assert result == ({"detail": "Alert not found"}, 404)
    mock_service.get_alert.assert_called_once_with("not-found-id")
