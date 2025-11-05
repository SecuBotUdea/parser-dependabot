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
        created_at="2024-06-01T00:00:00Z"
    )
    
    result = alert_repository.upsert_alert(alert)
    
    assert result is not None, "upsert_alert debe retornar un resultado"
    assert len(result) > 0, "upsert_alert debe retornar al menos un registro"
    assert result[0]['id'] == "test-alert-123", f"ID esperado: test-alert-123, obtenido: {result[0].get('id')}"
    
    # Cleanup
    alert_repository.supabase.table("alerts").delete().eq('id', result[0]['id']).execute()


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
        created_at="2024-06-01T00:00:00Z"
    )
    insert_result = alert_repository.upsert_alert(alert)
    alert_id = insert_result[0]['id']
    
    # Test
    result = alert_repository.get_alert_by_id(alert_id)
    
    assert result is not None, "get_alert_by_id debe retornar un resultado"
    assert result['id'] == alert_id, f"ID esperado: {alert_id}, obtenido: {result.get('id')}"
    assert result['cve'] == "TEST-GET-001", f"CVE esperado: TEST-GET-001, obtenido: {result.get('cve')}"
    
    # Cleanup
    alert_repository.supabase.table("alerts").delete().eq('id', alert_id).execute()


@pytest.mark.repository
def test_upsert_update_alert(alert_repository):
    """Actualiza un alert existente."""
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
        created_at="2024-06-01T00:00:00Z"
    )
    alert_repository.upsert_alert(alert)
    
    # Test
    alert_updated = AlertModel(
        id="test-update-123",
        repo="updated-repo",
        source="dependabot",
        severity=5.0,
        cvss=5.0,
        cve="TEST-UPDATE-001",
        description="Updated",
        package={},
        location={},
        raw={},
        created_at="2024-06-01T00:00:00Z"
    )
    result = alert_repository.upsert_alert(alert_updated)
    
    assert result[0]['description'] == "Updated", f"Descripción esperada: 'Updated', obtenida: '{result[0].get('description')}'"
    assert result[0]['repo'] == "updated-repo", f"Repo esperado: 'updated-repo', obtenido: '{result[0].get('repo')}'"
    
    # Cleanup
    alert_repository.supabase.table("alerts").delete().eq('id', "test-update-123").execute()
