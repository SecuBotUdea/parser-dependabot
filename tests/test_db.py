# tests/test_db.py
import os
from unittest.mock import MagicMock

import pytest

import app.db as db

SAMPLE_ALERT = {
    "id": "PangoAguirre/aprendiendo-react#33",
    "source": "dependabot",
    "created_at": "2025-10-18T02:21:07+00:00",
    "package": {
        "name": "vite",
        "ecosystem": "npm",
        "current_version": ">=6.0.0, <=6.3.5",
        "fixed_version": "6.3.6",
    },
    "severity": "low",
    "cvss": 2.3,
    "cve": ["CVE-2025-58751"],
    "description": "Some summary",
    "location": {
        "file": "projects/05-react-buscador-pelicula/pnpm-lock.yaml",
        "path": "PangoAguirre/aprendiendo-react/projects/05-react-buscador-pelicula/pnpm-lock.yaml",
        "line": None,
    },
    "raw": {"some": "payload"},
}


def make_mock_conn_and_cursor():
    conn = MagicMock(name="pg_conn")
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = None

    cur = MagicMock(name="cursor")
    cursor_cm = MagicMock(name="cursor_cm")
    cursor_cm.__enter__.return_value = cur
    cursor_cm.__exit__.return_value = None

    conn.cursor.return_value = cursor_cm
    return conn, cur


def test_upsert_alert_executes_sql_and_closes_connection(monkeypatch):
    # Forzar DATABASE_URL en el módulo importado
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pass@localhost/db")
    db.DATABASE_URL = os.getenv("DATABASE_URL")

    # Mock conexión
    conn_mock, cur_mock = make_mock_conn_and_cursor()
    monkeypatch.setattr(db.psycopg2, "connect", lambda dsn: conn_mock)

    # Ejecutar la función
    db.upsert_alert(SAMPLE_ALERT)

    # Aserciones
    assert cur_mock.execute.call_count == 1
    sql, params = cur_mock.execute.call_args[0]
    assert "INSERT INTO alerts" in sql
    assert params["id"] == SAMPLE_ALERT["id"]
    assert params["repo"] == SAMPLE_ALERT["id"].split("#")[0]
    assert "normalized" in params
    assert "raw" in params
    # conexión cerrada
    assert conn_mock.close.call_count == 1


def test_upsert_alert_closes_connection_on_exception(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pass@localhost/db")
    db.DATABASE_URL = os.getenv("DATABASE_URL")

    conn_mock, cur_mock = make_mock_conn_and_cursor()
    cur_mock.execute.side_effect = RuntimeError("DB execution failed")
    monkeypatch.setattr(db.psycopg2, "connect", lambda dsn: conn_mock)

    with pytest.raises(RuntimeError):
        db.upsert_alert(SAMPLE_ALERT)

    assert conn_mock.close.call_count == 1
