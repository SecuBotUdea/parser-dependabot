from typing import Optional

from app.models.alert_model import Alert as AlertModel
from app.repositories.base_repo import BaseRepository
from app.services.mappers.dependabot_mapper import DependabotMapper
from app.services.mappers.zap_mapper import ZapMapper


class AlertService:
    """
    Servicio para manejar la lógica de negocio de alertas.
    """

    def __init__(self, alert_repository: BaseRepository[AlertModel]):
        self.alert_repository = alert_repository
        self.dependabot_mapper = DependabotMapper()
        self.zap_mapper = ZapMapper()

    def create_alert_from_dependabot(self, webhook_data: dict) -> AlertModel:
        """
        Procesa un webhook de Dependabot y crea/actualiza un alert.

        Args:
            webhook_data: Datos completos del webhook de Dependabot

        Returns:
            AlertModel: Alert creado/actualizado
        """
        # Mapear datos
        alert = self.dependabot_mapper.map_to_alert(webhook_data)

        # Persistir
        return self.alert_repository.upsert(alert)

    def create_alert_from_zap(self, zap_data: dict) -> list[AlertModel]:
        """
        Procesa un reporte de OWASP ZAP y crea/actualiza múltiples alerts.

        Args:
            zap_data: Datos completos del reporte JSON de OWASP ZAP

        Returns:
            list[AlertModel]: Lista de alerts creados/actualizados
        """
        # Mapear datos (ZAP puede generar múltiples alertas)
        alerts = self.zap_mapper.map_to_alerts(zap_data)

        # Persistir cada alerta
        created_alerts = []
        for alert in alerts:
            created_alert = self.alert_repository.upsert(alert)
            created_alerts.append(created_alert)

        return created_alerts

    def get_alert(self, alert_id: str) -> Optional[AlertModel]:
        """
        Obtiene un alert por su ID.

        Args:
            alert_id: ID del alert

        Returns:
            AlertModel o None si no existe
        """
        return self.alert_repository.get_by_id(alert_id)
