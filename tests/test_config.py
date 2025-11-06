from unittest.mock import MagicMock, patch

import pytest

import app.core.config as config


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    """Configura variables de entorno simuladas antes de cada test."""
    monkeypatch.setenv("SUPABASE_URL", "https://fake.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "fake-key-123")


def test_get_supabase_calls_create_client(monkeypatch):
    """Verifica que get_supabase llame a create_client con los valores esperados."""
    mock_client = MagicMock(name="SupabaseClientMock")

    with patch(
        "app.core.config.create_client", return_value=mock_client
    ) as mock_create:
        client = config.get_supabase()

    mock_create.assert_called_once_with("https://fake.supabase.co", "fake-key-123")

    assert client == mock_client


def test_get_supabase_uses_env_values(monkeypatch):
    """Verifica que el módulo lea las variables de entorno correctamente."""
    monkeypatch.setenv("SUPABASE_URL", "https://demo.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "super-secret-key")

    with patch(
        "app.core.config.create_client", return_value="client-ok"
    ) as mock_create:
        result = config.get_supabase()

    mock_create.assert_called_once_with("https://demo.supabase.co", "super-secret-key")
    assert result == "client-ok"
