import logging

from fastapi import HTTPException

from app.core.config import get_supabase
from app.repositories.alert_repo import AlertRepository
from app.services.alert_service import AlertService


def get_alert_service() -> AlertService:
    try:
        supabase = get_supabase()
        repo = AlertRepository(supabase)
        return AlertService(repo)
    except Exception as e:
        logging.error(f"Error initializing AlertService dependencies: {e}")
        raise HTTPException(
            status_code=500, detail="Internal Server Error: Database dependency failed."
        )
