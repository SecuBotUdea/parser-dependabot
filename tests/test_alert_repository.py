import pytest

from app.core.config import get_supabase
from app.models.alert_model import AlertModel
from app.repositories.alert_repo import AlertRepository


@pytest.fixture
def alert_repository():
    """Proporciona una instancia de AlertRepository."""
    supabase = get_supabase()
    return AlertRepository(supabase)


@pytest.mark.repository
def test_upsert_new_alert(alert_repository):
    """Inserta un nuevo alert."""
    alert = AlertModel(
        id="test-alert-123",
        repo="test-repo",
        source="dependabot",
        severity=4.5,
        cvss=4.0,
        cve="TEST-2024-0001",
        description="Test alert description",
        package={},
        location={},
        raw={},
        created_at="2024-06-01T00:00:00Z",
    )

    result = alert_repository.upsert(alert)

    assert result is not None, "upsert debe retornar un resultado"
    assert (
        result.id == "test-alert-123"
    ), f"ID esperado: test-alert-123, obtenido: {result.id}"

    # Cleanup
    alert_repository.supabase.table("alerts").delete().eq("id", result.id).execute()


@pytest.mark.repository
def test_get_alert_by_id(alert_repository):
    """Obtiene un alert por ID."""
    # Setup
    alert = AlertModel(
        id="test-get-123",
        repo="test-repo",
        source="dependabot",
        severity=3.0,
        cvss=3.0,
        cve="TEST-GET-001",
        description="Test get",
        package={},
        location={},
        raw={},
        created_at="2024-06-01T00:00:00Z",
    )
    alert_repository.upsert(alert)

    # Test
    result = alert_repository.get_by_id("test-get-123")

    assert result is not None, "get_by_id debe retornar un resultado"
    assert (
        result.id == "test-get-123"
    ), f"ID esperado: test-get-123, obtenido: {result.id}"
    assert (
        result.cve == "TEST-GET-001"
    ), f"CVE esperado: TEST-GET-001, obtenido: {result.cve}"

    # Cleanup
    alert_repository.supabase.table("alerts").delete().eq(
        "id", "test-get-123"
    ).execute()


@pytest.mark.repository
def test_upsert_update_alert(alert_repository):
    """Actualiza un alert existente usando upsert."""
    # Setup
    alert = AlertModel(
        id="test-update-123",
        repo="original-repo",
        source="dependabot",
        severity=2.0,
        cvss=2.0,
        cve="TEST-UPDATE-001",
        description="Original",
        package={},
        location={},
        raw={},
        created_at="2024-06-01T00:00:00Z",
    )
    alert_repository.upsert(alert)

    # Test
    alert.description = "Updated"
    alert.repo = "updated-repo"
    result = alert_repository.upsert(alert)

    assert (
        result.description == "Updated"
    ), f"Descripción esperada: 'Updated', obtenida: '{result.description}'"
    assert (
        result.repo == "updated-repo"
    ), f"Repo esperado: 'updated-repo', obtenido: '{result.repo}'"

    # Cleanup
    alert_repository.supabase.table("alerts").delete().eq(
        "id", "test-update-123"
    ).execute()
