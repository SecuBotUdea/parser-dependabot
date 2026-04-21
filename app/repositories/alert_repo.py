from typing import Optional

from supabase import Client

from app.models.alert_model import Alert as AlertModel
from app.repositories.base_repo import BaseRepository


class AlertRepository(BaseRepository[AlertModel]):
    """Repositorio para manejar operaciones de Alert en Supabase."""

    def __init__(self, supabase: Client):
        self.supabase = supabase
        self.table_name = "alert"

    def upsert(self, entity: AlertModel) -> AlertModel:
        """Inserta o actualiza un alert."""
        data = entity.model_dump(mode="json")
        response = self.supabase.table(self.table_name).upsert(data).execute()

        if not response.data:
            raise Exception("No se pudo realizar el upsert en la tabla alert")

        known_fields = {
            k: v for k, v in response.data[0].items() if k in AlertModel.model_fields
        }
        return AlertModel(**known_fields)

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
            print(f"Error al obtener alerta: {e}")  # Útil para debug escolar
            return None
