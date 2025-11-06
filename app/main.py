from fastapi import FastAPI

from app.hooks.webhook import router as webhook_router

app = FastAPI(title="Parser Dependabot")

app.include_router(webhook_router)


# ---------- Ruta de salud ----------
@app.get("/")
def health_check():
    return {"status": "ok"}
