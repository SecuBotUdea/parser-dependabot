from fastapi.testclient import TestClient

from app.main import app


def test_health_check():
    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_webhook_router_included():
    routes = [route.path for route in app.routes]
    assert any("webhook" in path for path in routes)
