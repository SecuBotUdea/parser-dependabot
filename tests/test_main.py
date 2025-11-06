from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.main import app
from app.routes.items.get_alert_service import get_alert_service

client = TestClient(app)


def test_health_check():
    """Debe devolver estado OK en la ruta raíz."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_get_alert_found():
    """Debe devolver una alerta existente."""
    mock_service = MagicMock()
    mock_service.get_alert.return_value = {
        "id": "123",
        "name": "Critical Vulnerability",
        "severity": "high",
    }

    # Sobrescribimos la dependencia original
    app.dependency_overrides[get_alert_service] = lambda: mock_service

    response = client.get("/alerts/123")

    assert response.status_code == 200
    assert response.json() == {
        "id": "123",
        "name": "Critical Vulnerability",
        "severity": "high",
    }
    mock_service.get_alert.assert_called_once_with("123")

    # Limpieza
    app.dependency_overrides.clear()


def test_get_alert_not_found():
    """Debe devolver 404 si la alerta no existe."""
    mock_service = MagicMock()
    mock_service.get_alert.return_value = None

    app.dependency_overrides[get_alert_service] = lambda: mock_service

    response = client.get("/alerts/999")

    assert response.status_code == 404
    assert response.json() == {"detail": "Alert with ID '999' not found"}
    mock_service.get_alert.assert_called_once_with("999")

    app.dependency_overrides.clear()


def test_webhook_router_included():
    routes = [route.path for route in app.routes]
    assert any("webhook" in path for path in routes)
