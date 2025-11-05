from typing import Optional
from app.models.alert_model import AlertModel
from app.repositories.base_repo import BaseRepository
from app.services.mappers.dependabot_mapper import DependabotMapper


class AlertService:
    """
    Servicio para manejar la lógica de negocio de alertas.
    """
    
    def __init__(self, alert_repository: BaseRepository[AlertModel]):
        self.alert_repository = alert_repository
        self.mapper = DependabotMapper()
    
    def create_alert_from_dependabot(self, webhook_data: dict) -> AlertModel:
        """
        Procesa un webhook de Dependabot y crea/actualiza un alert.
        
        Args:
            webhook_data: Datos completos del webhook de Dependabot
            
        Returns:
            AlertModel: Alert creado/actualizado
        """
        # Mapear datos
        alert = self.mapper.map_to_alert(webhook_data)
        
        # Persistir
        return self.alert_repository.upsert(alert)
    
    def get_alert(self, alert_id: str) -> Optional[AlertModel]:
        """
        Obtiene un alert por su ID.
        
        Args:
            alert_id: ID del alert
            
        Returns:
            AlertModel o None si no existe
        """
        return self.alert_repository.get_by_id(alert_id)
