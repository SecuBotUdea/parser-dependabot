from fastapi import Depends, FastAPI, HTTPException

from app.routes.items.get_alert_service import get_alert_service
from app.routes.webhook import router as webhook_router
from app.services.alert_service import AlertService

app = FastAPI(title="Parser Dependabot")

app.include_router(webhook_router)


# ---------- Ruta de salud ----------
@app.get("/")
def health_check():
    return {"status": "ok"}


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str, service: AlertService = Depends(get_alert_service)):
    alert = service.get_alert(alert_id)

    if alert:
        return alert

    raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found")
