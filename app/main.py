from fastapi import FastAPI

app = FastAPI(title="Parser Dependabot")

# app.include_router(webhook_router)


# ---------- Ruta de salud ----------
@app.get("/")
def health_check():
    return {"status": "ok"}
