from db.connection import close_pool, init_pool
from fastapi import FastAPI
from hooks.webhook import router as webhook_router

app = FastAPI(title="Parser Dependabot")

app.include_router(webhook_router)


@app.on_event("startup")
def on_startup():
    init_pool()
    print("✅ Conexión a la base de datos inicializada.")


@app.on_event("shutdown")
def on_shutdown():
    close_pool()
    print("🧹 Conexiones a la base de datos cerradas.")


# ---------- Ruta de salud ----------
@app.get("/", tags=["health"])
def health_check():
    return {"status": "ok"}
