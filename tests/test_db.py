# tests/test_db.py
import os
from unittest.mock import MagicMock

import pytest

from app.hooks import db

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


def _extract_execute_args(call):
    """
    Extrae (sql, params) desde call_args de un MagicMock de execute de forma robusta.
    call es cur_mock.execute.call_args
    """
    pos_args = call[0] or ()
    kw_args = call[1] or {}

    sql = None
    params = None

    if len(pos_args) >= 1:
        sql = pos_args[0]
    if len(pos_args) >= 2:
        params = pos_args[1]

    # Intentar encontrar params en kwargs (varios nombres posibles)
    if params is None:
        for k in ("params", "vars", "parameters", "args"):
            if k in kw_args:
                params = kw_args[k]
                break

    # A veces se pasa solo sql y los parámetros como kwargs (raro), intentar detectar dict en kwargs
    if params is None and isinstance(kw_args, dict):
        # buscar el primer valor de tipo dict en kwargs
        for v in kw_args.values():
            if isinstance(v, dict):
                params = v
                break

    return sql, params


def test_upsert_alert_executes_sql_and_closes_connection(monkeypatch):
    # Forzar DATABASE_URL en el módulo importado
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pass@localhost/db")
    db.DATABASE_URL = os.getenv("DATABASE_URL")

    # Mock conexión
    conn_mock, cur_mock = make_mock_conn_and_cursor()
    monkeypatch.setattr(db.psycopg2, "connect", lambda dsn: conn_mock)

    # Ejecutar la función
    db.upsert_alert(SAMPLE_ALERT)

    # Aserciones: execute fue llamado
    assert cur_mock.execute.call_count == 1

    # Extraer sql y params de forma robusta
    call = cur_mock.execute.call_args
    sql, params = _extract_execute_args(call)

    assert sql and isinstance(
        sql, str
    ), "No se pudo extraer la cadena SQL de cur.execute"
    assert "INSERT INTO alerts" in sql

    assert params is not None and isinstance(
        params, dict
    ), f"Parámetros inesperados: {params!r}"

    # Verificaciones sobre los parámetros
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
