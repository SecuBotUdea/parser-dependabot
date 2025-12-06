import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import app.routes.webhook as webhook
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


@pytest.fixture
def zap_payload():
    """Payload de OWASP ZAP para tests."""
    return {
        "source": "owasp_zap",
        "scan_date": "2025-12-05T22:10:29Z",
        "repository": "test/repo",
        "run_id": "123456",
        "payload": {
            "@version": "2.16.1",
            "@generated": "2025-12-05T22:10:29",
            "site": [
                {
                    "@name": "https://test.com",
                    "alerts": [
                        {
                            "pluginid": "40048",
                            "alert": "Test Vulnerability",
                            "riskcode": "3",
                            "cweid": "78",
                            "desc": "Test description",
                            "instances": [],
                            "count": "1",
                        }
                    ],
                }
            ],
        },
    }


@patch("app.routes.webhook._enqueue_upsert", new_callable=AsyncMock)
def test_webhook_zap_valid_event(mock_enqueue, zap_payload):
    """Debe aceptar y encolar un evento de OWASP ZAP si la firma es válida."""
    client = TestClient(app)
    body = json.dumps(zap_payload).encode()
    signature = generate_signature(body, "testsecret")

    headers = {
        "x-hub-signature-256": signature,
        "x-github-event": "",  # ZAP no tiene x-github-event
        "x-github-delivery": "zap-delivery-123",
        "content-type": "application/json",
    }

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}

    # Verificar que se llamó con el source correcto
    mock_enqueue.assert_awaited_once()
    call_args = mock_enqueue.call_args
    assert call_args[1]["source"] == "owasp_zap"


@patch("app.routes.webhook._enqueue_upsert", new_callable=AsyncMock)
def test_webhook_zap_detects_source_from_payload(mock_enqueue, zap_payload):
    """Debe detectar el source 'owasp_zap' desde el payload."""
    client = TestClient(app)
    body = json.dumps(zap_payload).encode()
    signature = generate_signature(body, "testsecret")

    headers = {
        "x-hub-signature-256": signature,
        "content-type": "application/json",
    }

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 200

    # Verificar que extrajo el payload interno
    call_args = mock_enqueue.call_args
    payload_arg = call_args[0][0]  # Primer argumento posicional

    # Debe tener la estructura del reporte ZAP interno
    assert "@version" in payload_arg
    assert "site" in payload_arg


@patch("app.routes.webhook._enqueue_upsert", new_callable=AsyncMock)
def test_webhook_zap_invalid_signature(mock_enqueue, zap_payload):
    """Debe rechazar evento de ZAP con firma inválida."""
    client = TestClient(app)
    body = json.dumps(zap_payload).encode()

    headers = {
        "x-hub-signature-256": "sha256=invalidsignature",
        "content-type": "application/json",
    }

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid signature"}
    mock_enqueue.assert_not_awaited()


@patch("app.routes.webhook._enqueue_upsert", new_callable=AsyncMock)
def test_webhook_zap_multiple_alerts(mock_enqueue):
    """Debe manejar reporte de ZAP con múltiples alertas."""
    client = TestClient(app)

    payload = {
        "source": "owasp_zap",
        "payload": {
            "@version": "2.16.1",
            "site": [
                {
                    "@name": "https://multi-test.com",
                    "alerts": [
                        {
                            "pluginid": "10038",
                            "alert": "CSP Not Set",
                            "riskcode": "2",
                        },
                        {
                            "pluginid": "10095",
                            "alert": "XSS",
                            "riskcode": "3",
                        },
                    ],
                }
            ],
        },
    }

    body = json.dumps(payload).encode()
    signature = generate_signature(body, "testsecret")

    headers = {
        "x-hub-signature-256": signature,
        "content-type": "application/json",
    }

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 200
    mock_enqueue.assert_awaited_once()

    # Verificar que el payload tiene 2 alertas
    call_args = mock_enqueue.call_args
    payload_arg = call_args[0][0]
    assert len(payload_arg["site"][0]["alerts"]) == 2


@patch("app.routes.webhook._enqueue_upsert", new_callable=AsyncMock)
def test_webhook_distinguishes_dependabot_and_zap(mock_enqueue):
    """Debe distinguir entre eventos de Dependabot y ZAP."""
    client = TestClient(app)

    # Evento de Dependabot (tiene x-github-event)
    dependabot_payload = {"alert": {"id": 1}, "repository": {"name": "test"}}
    body_dep = json.dumps(dependabot_payload).encode()
    sig_dep = generate_signature(body_dep, "testsecret")

    response_dep = client.post(
        "/webhook",
        data=body_dep,
        headers={
            "x-hub-signature-256": sig_dep,
            "x-github-event": "dependabot_alert",
            "content-type": "application/json",
        },
    )

    assert response_dep.status_code == 200
    call_args_dep = mock_enqueue.call_args
    assert call_args_dep[1]["source"] == "dependabot"

    mock_enqueue.reset_mock()

    # Evento de ZAP (tiene source en payload)
    zap_payload = {
        "source": "owasp_zap",
        "payload": {"@version": "2.16.1", "site": []},
    }
    body_zap = json.dumps(zap_payload).encode()
    sig_zap = generate_signature(body_zap, "testsecret")

    response_zap = client.post(
        "/webhook",
        data=body_zap,
        headers={
            "x-hub-signature-256": sig_zap,
            "content-type": "application/json",
        },
    )

    assert response_zap.status_code == 200
    call_args_zap = mock_enqueue.call_args
    assert call_args_zap[1]["source"] == "owasp_zap"
