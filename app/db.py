import os
from psycopg2.extras import Json
import psycopg2

DATABASE_URL = os.getenv("DATABASE_URL")

def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)

def upsert_alert(alert: dict):
    """
    Inserta o actualiza (upsert) la alerta en la tabla alerts.
    Nota: conexión simple; para producción usar pool.
    """
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                sql = """
                INSERT INTO alerts (id, repo, normalized, raw, source, created_at, ingested_at, last_seen_at, status)
                VALUES (%s,%s,%s,%s,%s,%s,now(),now(),'open')
                ON CONFLICT (id) DO UPDATE SET
                  normalized = EXCLUDED.normalized,
                  raw = EXCLUDED.raw,
                  last_seen_at = now();
                """
                repo = alert["id"].split("#")[0]
                cur.execute(sql, (
                    alert["id"],
                    repo,
                    Json(alert),  # normalized
                    Json(alert.get("raw", {})),
                    alert.get("source", "dependabot"),
                    alert.get("created_at", None)
                ))
    finally:
        conn.close()
