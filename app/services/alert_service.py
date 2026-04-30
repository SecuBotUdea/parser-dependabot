from typing import Optional

from app.models.alert_model import Alert as AlertModel
from app.repositories.base_repo import BaseRepository
from app.services.mappers.dependabot_mapper import DependabotMapper
from app.services.mappers.trivy_mapper import TrivyMapper
from app.services.mappers.zap_mapper import ZapMapper


class AlertService:

    def __init__(self, alert_repository: BaseRepository[AlertModel]):
        self.alert_repository = alert_repository

    def create_alert_from_dependabot(self, alert_data: dict) -> AlertModel:
        """
        Args:
            alert_data: Contenido del campo 'alert' del webhook de Dependabot,
                        no el webhook completo.
        """
        alert = DependabotMapper.map_to_alert(alert_data)
        return self.alert_repository.upsert(alert)

    def create_alert_from_zap(self, zap_data: dict) -> list[AlertModel]:
        alerts = ZapMapper.map_to_alerts(zap_data)
        return [self.alert_repository.upsert(alert) for alert in alerts]

    def create_alert_from_trivy(self, trivy_data: dict) -> list[AlertModel]:
        alerts = TrivyMapper.map_to_alerts(trivy_data)
        return [self.alert_repository.upsert(alert) for alert in alerts]

    def get_alert(self, alert_id: str) -> Optional[AlertModel]:
        return self.alert_repository.get_by_id(alert_id)
