import hashlib
import hmac
import importlib
import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import app.routes.webhook as webhook
import app.routes.webhook.router  # fuerza registro en sys.modules
from app.main import app
from app.routes.items.get_alert_service import get_alert_service
from app.services.alert_service import AlertService


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    """
    Configura entorno controlado para tests del router:
    - Parchea variables de módulo de router.py y security.py directamente,
      porque se cargan en tiempo de importación y monkeypatch.setenv no las actualiza.
    - Sobreescribe la dependencia de Supabase para evitar conexiones reales.
    """
    # sys.modules evita la colisión entre el módulo router.py y la variable
    # `router` (APIRouter) que __init__.py exporta con el mismo nombre
    router_mod = sys.modules["app.routes.webhook.router"]
    import app.routes.webhook.security as security_mod

    # Parchear variables de módulo en router.py
    monkeypatch.setattr(router_mod, "DEBUG", True)
    monkeypatch.setattr(router_mod, "WEBHOOK_SECRET", "testsecret")

    # Parchear el secret en security.py para que verify_signature acepte la firma
    monkeypatch.setattr(security_mod, "WEBHOOK_SECRET", "testsecret")
    monkeypatch.setattr(security_mod, "WEBHOOK_SECRET_BYTES", b"testsecret")

    # Evitar que FastAPI intente conectarse a Supabase
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


@patch("app.routes.webhook.router._enqueue_upsert", new_callable=AsyncMock)
def test_router_dispatches_none_when_alert_key_missing(mock_enqueue):
    """
    Bug T-R1: el router no valida que payload["alert"] exista antes de despachar.

    Si el payload de Dependabot llega sin la clave "alert" (formato inesperado,
    payload incompleto, o fuente externa mal configurada), payload.get("alert")
    retorna None. El router igual llama a _enqueue_upsert(None, ...) y responde
    "accepted" como si todo fuera correcto.

    Desde afuera el webhook parece haber funcionado. Internamente, None llega
    al procesador y desencadena el doble fallo documentado en T-P1.

    Este test verifica el comportamiento actual: el router acepta y despacha
    aunque alert_data sea None, documentando el bug antes de corregirlo.
    """
    client = TestClient(app)
    payload = {"repository": {"full_name": "org/repo"}, "sender": {"login": "bot"}}
    body = json.dumps(payload).encode()

    response = client.post("/webhook", data=body, headers=dependabot_headers(body))

    # El router responde accepted sin validar que "alert" exista
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}

    # _enqueue_upsert fue llamado con None como primer argumento
    args, kwargs = mock_enqueue.call_args
    assert args[0] is None, (
        "Se esperaba que alert_data fuera None cuando falta la clave 'alert' en el payload"
    )


@patch("app.routes.webhook.router._enqueue_upsert", new_callable=AsyncMock)
def test_router_dispatches_correct_alert_subobject(mock_enqueue):
    """
    T-R2: el router debe pasar payload["alert"] (el sub-objeto), no el payload completo.

    Verifica que _enqueue_upsert recibe exactamente el contenido de la clave "alert",
    no el webhook entero. Si se pasara el payload completo, el mapper no encontraría
    los campos esperados y generaría un alert con valores por defecto vacíos.
    """
    client = TestClient(app)
    alert_data = {"number": 42, "state": "open", "html_url": "https://github.com/org/repo/security/dependabot/42"}
    payload = {"alert": alert_data, "repository": {"full_name": "org/repo"}}
    body = json.dumps(payload).encode()

    response = client.post("/webhook", data=body, headers=dependabot_headers(body))

    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}

    args, kwargs = mock_enqueue.call_args
    assert args[0] == alert_data, (
        "El router debe pasar payload['alert'] a _enqueue_upsert, no el payload completo"
    )
