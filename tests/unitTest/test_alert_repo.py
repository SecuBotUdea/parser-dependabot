from unittest.mock import MagicMock

import pytest

from app.models.alert_model import Alert as AlertModel
from app.repositories.alert_repo import AlertRepository


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_repo() -> tuple[AlertRepository, MagicMock]:
    mock_supabase = MagicMock()
    repo = AlertRepository(mock_supabase)
    return repo, mock_supabase


def minimal_alert_dict() -> dict:
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
# T-RR1 — upsert: manejo de campos extra de Supabase
# ---------------------------------------------------------------------------

def test_upsert_succeeds_when_supabase_returns_extra_fields():
    # Arrange
    repo, mock_supabase = make_repo()
    response_with_extra = {**minimal_alert_dict(), "created_by": "system_internal"}
    mock_supabase.table.return_value.upsert.return_value.execute.return_value.data = [
        response_with_extra
    ]

    # Act
    result = repo.upsert(AlertModel(**minimal_alert_dict()))

    # Assert
    assert isinstance(result, AlertModel)
    assert result.alert_id == "dependabot-org-repo-42"


def test_upsert_succeeds_when_supabase_returns_clean_data():
    # Arrange
    repo, mock_supabase = make_repo()
    mock_supabase.table.return_value.upsert.return_value.execute.return_value.data = [
        minimal_alert_dict()
    ]

    # Act
    result = repo.upsert(AlertModel(**minimal_alert_dict()))

    # Assert
    assert isinstance(result, AlertModel)
    assert result.alert_id == "dependabot-org-repo-42"


# ---------------------------------------------------------------------------
# T-RR2 — upsert: respuesta vacía y nombre de tabla
# ---------------------------------------------------------------------------

def test_upsert_raises_exception_when_response_data_is_empty():
    # Arrange
    repo, mock_supabase = make_repo()
    mock_supabase.table.return_value.upsert.return_value.execute.return_value.data = []

    # Act / Assert
    with pytest.raises(Exception) as exc_info:
        repo.upsert(AlertModel(**minimal_alert_dict()))

    assert "upsert" in str(exc_info.value).lower()


def test_upsert_calls_supabase_with_correct_table_name():
    # Arrange
    repo, mock_supabase = make_repo()
    mock_supabase.table.return_value.upsert.return_value.execute.return_value.data = [
        minimal_alert_dict()
    ]

    # Act
    repo.upsert(AlertModel(**minimal_alert_dict()))

    # Assert
    mock_supabase.table.assert_called_once_with("alert")


# ---------------------------------------------------------------------------
# T-RR3 — get_by_id
# ---------------------------------------------------------------------------

def test_get_by_id_returns_none_when_record_does_not_exist():
    # Arrange
    repo, mock_supabase = make_repo()
    mock_supabase.table.return_value.select.return_value.eq.return_value \
        .maybe_single.return_value.execute.return_value.data = None

    # Act
    result = repo.get_by_id("id-que-no-existe")

    # Assert
    assert result is None


def test_get_by_id_returns_alert_model_when_record_exists():
    # Arrange
    repo, mock_supabase = make_repo()
    mock_supabase.table.return_value.select.return_value.eq.return_value \
        .maybe_single.return_value.execute.return_value.data = minimal_alert_dict()

    # Act
    result = repo.get_by_id("dependabot-org-repo-42")

    # Assert
    assert isinstance(result, AlertModel)
    assert result.alert_id == "dependabot-org-repo-42"


def test_get_by_id_queries_by_alert_id_field():
    # Arrange
    repo, mock_supabase = make_repo()
    mock_supabase.table.return_value.select.return_value.eq.return_value \
        .maybe_single.return_value.execute.return_value.data = minimal_alert_dict()

    # Act
    repo.get_by_id("dependabot-org-repo-42")

    # Assert
    mock_supabase.table.return_value.select.return_value.eq.assert_called_once_with(
        "alert_id", "dependabot-org-repo-42"
    )
