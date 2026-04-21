import hashlib
import hmac
import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import app.routes.webhook.router
from app.main import app
from app.routes.items.get_alert_service import get_alert_service
from app.services.alert_service import AlertService


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    """
    Configura entorno controlado para todos los tests del router:
    - Parchea variables de módulo cargadas en tiempo de importación
    - Sobreescribe la dependencia de Supabase para evitar conexiones reales
    """
    router_mod = sys.modules["app.routes.webhook.router"]
    import app.routes.webhook.security as security_mod

    monkeypatch.setattr(router_mod, "DEBUG", True)
    monkeypatch.setattr(router_mod, "WEBHOOK_SECRET", "testsecret")
    monkeypatch.setattr(security_mod, "WEBHOOK_SECRET", "testsecret")
    monkeypatch.setattr(security_mod, "WEBHOOK_SECRET_BYTES", b"testsecret")

    mock_service = MagicMock(spec=AlertService)
    app.dependency_overrides[get_alert_service] = lambda: mock_service

    yield

    app.dependency_overrides.clear()


def make_signature(body: bytes, secret: str = "testsecret") -> str:
    mac = hmac.new(secret.encode(), msg=body, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def dependabot_headers(body: bytes) -> dict:
    return {
        "x-hub-signature-256": make_signature(body),
        "x-github-event": "dependabot_alert",
        "x-github-delivery": "test-delivery-001",
        "content-type": "application/json",
    }


# ---------------------------------------------------------------------------
# T-R1 — validación de la clave "alert" en el payload
# ---------------------------------------------------------------------------

@patch("app.routes.webhook.router._enqueue_upsert", new_callable=AsyncMock)
def test_router_returns_422_when_alert_key_missing(mock_enqueue):
    # Arrange (env y mock service configurados por fixture setup_env)
    client = TestClient(app)
    payload = {"repository": {"full_name": "org/repo"}, "sender": {"login": "bot"}}
    body = json.dumps(payload).encode()

    # Act
    response = client.post("/webhook", data=body, headers=dependabot_headers(body))

    # Assert
    assert response.status_code == 422
    mock_enqueue.assert_not_called()


# ---------------------------------------------------------------------------
# T-R2 — extracción correcta del sub-objeto "alert"
# ---------------------------------------------------------------------------

@patch("app.routes.webhook.router._enqueue_upsert", new_callable=AsyncMock)
def test_router_dispatches_alert_subobject_to_enqueue(mock_enqueue):
    # Arrange (env y mock service configurados por fixture setup_env)
    client = TestClient(app)
    alert_data = {
        "number": 42,
        "state": "open",
        "html_url": "https://github.com/org/repo/security/dependabot/42",
    }
    payload = {"alert": alert_data, "repository": {"full_name": "org/repo"}}
    body = json.dumps(payload).encode()

    # Act
    response = client.post("/webhook", data=body, headers=dependabot_headers(body))

    # Assert
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}
    args, _ = mock_enqueue.call_args
    assert args[0] == alert_data
