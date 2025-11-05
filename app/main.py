from fastapi import FastAPI

from app.hooks.webhook import router as webhook_router

"""@asynccontextmanager
async def lifespan_handler(app: FastAPI):
    # --- STARTUP (Inicialización de Recursos) ---
    init_pool()
    print("✅ Conexión a la base de datos inicializada.")

    yield # La aplicación se mantiene activa aquí (se procesan las peticiones)

    # --- SHUTDOWN (Liberación de Recursos) ---
    close_pool()
    print("🧹 Conexiones a la base de datos cerradas.")"""

# 2. Inicializar FastAPI con el handler
app = FastAPI(title="Parser Dependabot")  # , lifespan=lifespan_handler)

app.include_router(webhook_router)


# ---------- Ruta de salud ----------
@app.get("/")
def health_check():
    return {"status": "ok"}
