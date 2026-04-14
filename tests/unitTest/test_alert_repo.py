from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.models.alert_model import Alert as AlertModel
from app.repositories.alert_repo import AlertRepository


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_repo() -> tuple[AlertRepository, MagicMock]:
    """Retorna un repositorio con un cliente Supabase completamente mockeado."""
    mock_supabase = MagicMock()
    repo = AlertRepository(mock_supabase)
    return repo, mock_supabase


def minimal_alert_dict() -> dict:
    """Dict mínimo que representa un Alert válido tal como lo devolvería Supabase."""
    return {
        "alert_id": "dependabot-org-repo-42",
        "source_type": "dependabot",
        "source_id": "42",
        "title": "Vulnerability in requests",
        "severity": "high",
        "status": "open",
        "component": "requests",
        "first_seen": "2024-01-01T00:00:00",
    }


# ---------------------------------------------------------------------------
# T-RR1 — upsert cuando Supabase devuelve campos extra
# ---------------------------------------------------------------------------

def test_upsert_fails_with_validation_error_when_supabase_returns_extra_fields():
    """
    Bug T-RR1: AlertRepository.upsert() reconstruye la alerta con AlertModel(**response.data[0]).
    Como Alert tiene extra="forbid", cualquier campo adicional que Supabase devuelva
    (ej. columnas internas como 'created_by', 'tenant_id') lanza ValidationError.

    El upsert se ejecutó correctamente en Supabase, pero el repositorio explota
    al intentar reconstruir el objeto de vuelta. La alerta quedó guardada en la
    base de datos pero el servicio recibe una excepción, como si hubiera fallado.
    """
    repo, mock_supabase = make_repo()

    # Supabase devuelve el registro con un campo extra no definido en Alert
    response_with_extra = {**minimal_alert_dict(), "created_by": "system_internal"}
    mock_supabase.table.return_value.upsert.return_value.execute.return_value.data = [
        response_with_extra
    ]

    with pytest.raises(ValidationError) as exc_info:
        repo.upsert(AlertModel(**minimal_alert_dict()))

    assert "created_by" in str(exc_info.value)


def test_upsert_succeeds_when_supabase_returns_clean_data():
    """
    T-RR1 (complemento): cuando Supabase devuelve exactamente los campos de Alert,
    el upsert debe reconstruir el objeto sin errores.

    Este test documenta el comportamiento correcto como línea base
    para comparar con T-RR1 y guiar el fix.
    """
    repo, mock_supabase = make_repo()

    mock_supabase.table.return_value.upsert.return_value.execute.return_value.data = [
        minimal_alert_dict()
    ]

    result = repo.upsert(AlertModel(**minimal_alert_dict()))

    assert isinstance(result, AlertModel)
    assert result.alert_id == "dependabot-org-repo-42"


# ---------------------------------------------------------------------------
# T-RR2 — upsert cuando response.data está vacío
# ---------------------------------------------------------------------------

def test_upsert_raises_exception_when_response_data_is_empty():
    """
    Bug T-RR2: cuando Supabase retorna response.data = [] (upsert sin resultado),
    el repositorio lanza Exception("No se pudo realizar el upsert en la tabla alert").

    El mensaje de error no incluye ningún detalle del error original de Supabase,
    lo que hace imposible diagnosticar por qué falló: ¿tabla inexistente?
    ¿permisos insuficientes? ¿constraint violation?
    """
    repo, mock_supabase = make_repo()

    mock_supabase.table.return_value.upsert.return_value.execute.return_value.data = []

    with pytest.raises(Exception) as exc_info:
        repo.upsert(AlertModel(**minimal_alert_dict()))

    assert "upsert" in str(exc_info.value).lower()


def test_upsert_calls_supabase_with_correct_table_name():
    """
    T-RR2 (complemento): el repositorio debe llamar a la tabla con el nombre exacto "alert".

    Si el nombre de la tabla en Supabase difiere (ej. "alerts" en plural),
    cada upsert fallará silenciosamente. Este test ancla el nombre esperado.
    """
    repo, mock_supabase = make_repo()

    mock_supabase.table.return_value.upsert.return_value.execute.return_value.data = [
        minimal_alert_dict()
    ]

    repo.upsert(AlertModel(**minimal_alert_dict()))

    mock_supabase.table.assert_called_once_with("alert")


# ---------------------------------------------------------------------------
# T-RR3 — get_by_id cuando el registro no existe
# ---------------------------------------------------------------------------

def test_get_by_id_returns_none_when_record_does_not_exist():
    """
    T-RR3: get_by_id debe retornar None cuando Supabase no encuentra el registro.

    El flujo de deduplicación puede llamar a get_by_id antes del upsert para
    verificar si la alerta ya existe. Si el método explotara en lugar de retornar
    None, el proceso completo fallaría en la primera alerta nueva.
    """
    repo, mock_supabase = make_repo()

    mock_supabase.table.return_value.select.return_value.eq.return_value \
        .maybe_single.return_value.execute.return_value.data = None

    result = repo.get_by_id("id-que-no-existe")

    assert result is None


def test_get_by_id_returns_alert_model_when_record_exists():
    """
    T-RR3 (complemento): cuando el registro existe, get_by_id debe retornar
    un AlertModel correctamente construido.
    """
    repo, mock_supabase = make_repo()

    mock_supabase.table.return_value.select.return_value.eq.return_value \
        .maybe_single.return_value.execute.return_value.data = minimal_alert_dict()

    result = repo.get_by_id("dependabot-org-repo-42")

    assert isinstance(result, AlertModel)
    assert result.alert_id == "dependabot-org-repo-42"


def test_get_by_id_queries_by_alert_id_field():
    """
    T-RR3 (complemento): la consulta debe filtrar por la columna "alert_id",
    no por otro campo como "id" o "source_id".

    Si la columna de filtro es incorrecta, la consulta retorna None siempre
    aunque el registro exista, haciendo que el sistema trate todas las alertas
    como nuevas y cree duplicados en cada webhook recibido.
    """
    repo, mock_supabase = make_repo()

    mock_supabase.table.return_value.select.return_value.eq.return_value \
        .maybe_single.return_value.execute.return_value.data = minimal_alert_dict()

    repo.get_by_id("dependabot-org-repo-42")

    mock_supabase.table.return_value.select.return_value.eq.assert_called_once_with(
        "alert_id", "dependabot-org-repo-42"
    )
