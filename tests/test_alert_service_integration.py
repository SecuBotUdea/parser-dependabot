import pytest

from app.core.config import get_supabase
from app.repositories.alert_repo import AlertRepository
from app.services.alert_service import AlertService


@pytest.fixture
def alert_service_real():
    """AlertService con repositorio real."""
    supabase = get_supabase()
    return AlertService(AlertRepository(supabase))


@pytest.mark.integration
def test_create_and_get_alert(alert_service_real, complete_webhook):
    """Crea y obtiene un alert (integración)."""
    # Create
    created = alert_service_real.create_alert_from_dependabot(complete_webhook)
    assert created.id is not None

    # Get
    retrieved = alert_service_real.get_alert(created.id)
    assert retrieved.id == created.id

    # Cleanup
    alert_service_real.alert_repository.supabase.table("alerts").delete().eq(
        "id", created.id
    ).execute()
