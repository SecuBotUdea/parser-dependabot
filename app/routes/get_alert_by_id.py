from app.routes.items.get_alert_service import get_alert_service

def get_alert_by_id(alert_id: str):
    service = get_alert_service()
    alert = service.get_alert(alert_id)
    if alert:
        return alert
    return {"detail": "Alert not found"}, 404