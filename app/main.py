from fastapi import FastAPI

from .webhook import router as webhook_router

app = FastAPI(title="Parser Dependabot")

# Registrar rutas del webhook
app.include_router(webhook_router)


@app.get("/health")
def health():
    return {"status": "ok"}
