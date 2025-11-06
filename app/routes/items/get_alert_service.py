from app.core.config import get_supabase
from app.repositories.alert_repo import AlertRepository
from app.services.alert_service import AlertService


def get_alert_service() -> AlertService:
    supabase = get_supabase()
    repo = AlertRepository(supabase)
    return AlertService(repo)