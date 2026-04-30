import logging
from typing import Optional

from supabase import Client

from app.models.alert_model import Alert as AlertModel
from app.repositories.base_repo import BaseRepository

logger = logging.getLogger("webhook.processor")


class AlertRepository(BaseRepository[AlertModel]):
    """Repositorio para manejar operaciones de Alert en Supabase."""

    def __init__(self, supabase: Client):
        self.supabase = supabase
        self.table_name = "alerts"

    def upsert(self, entity: AlertModel) -> tuple[AlertModel, Optional[str]]:
        """Inserta o actualiza un alert. Retorna (alert, previous_status)."""

        existing = self.get_by_id(entity.alert_id)
        previous_status = existing.status.value if existing else None

        data = entity.model_dump(mode="json", exclude_none=True)
        response = self.supabase.table(self.table_name).upsert(data).execute()

        if not response.data:
            raise Exception("No se pudo realizar el upsert en la tabla alert")

        return AlertModel(**response.data[0]), previous_status

    def get_by_id(self, entity_id: str) -> Optional[AlertModel]:
        """Obtiene un alert por su ID."""
        try:
            response = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("alert_id", entity_id)
                .maybe_single()
                .execute()
            )
            return AlertModel(**response.data) if response.data else None
        except Exception as e:
            logger.error("Error fetching alert by id=%s: %s", entity_id, e)
            return None
