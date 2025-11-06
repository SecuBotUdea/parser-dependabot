import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.routes import webhook
from app.main import app


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    """Configura entorno controlado para las pruebas."""
    monkeypatch.setenv("WEBHOOK_SECRET", "testsecret")
    monkeypatch.setenv("DEBUG", "true")
    # recargamos el módulo para que lea los nuevos valores
    import importlib

    importlib.reload(webhook)


def generate_signature(body: bytes, secret: str) -> str:
    """Genera una firma válida de tipo sha256=xxxx."""
    mac = hmac.new(secret.encode(), msg=body, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def test_webhook_invalid_signature():
    """Debe devolver 400 si la firma es incorrecta."""
    client = TestClient(app)

    body = json.dumps({"hello": "world"}).encode()
    headers = {
        "x-hub-signature-256": "sha256=invalidsignature",
        "x-github-event": "push",
        "x-github-delivery": "123",
        "content-type": "application/json",
    }

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid signature"}


def test_webhook_ping_event(monkeypatch):
    """Debe responder 'pong' ante un evento ping válido."""
    client = TestClient(app)
    body = json.dumps({"zen": "Keep it logically awesome"}).encode()
    signature = generate_signature(body, "testsecret")

    headers = {
        "x-hub-signature-256": signature,
        "x-github-event": "ping",
        "x-github-delivery": "abc123",
        "content-type": "application/json",
    }

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 200
    assert response.json() == {"status": "pong"}


@patch("app.hooks.webhook._enqueue_upsert", new_callable=AsyncMock)
def test_webhook_valid_event(mock_enqueue):
    """Debe aceptar y encolar el evento si la firma es válida."""
    client = TestClient(app)
    body = json.dumps({"id": "1", "message": "dependabot alert"}).encode()
    signature = generate_signature(body, "testsecret")

    headers = {
        "x-hub-signature-256": signature,
        "x-github-event": "dependabot_alert",
        "x-github-delivery": "xyz789",
        "content-type": "application/json",
    }

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}
    mock_enqueue.assert_awaited_once()
