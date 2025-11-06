from fastapi import FastAPI

from app.routes import get_alert_by_id
from app.routes.webhook import router as webhook_router

app = FastAPI(title="Parser Dependabot")

app.include_router(webhook_router)


# ---------- Ruta de salud ----------
@app.get("/")
def health_check():
    return {"status": "ok"}


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    return get_alert_by_id(alert_id)
