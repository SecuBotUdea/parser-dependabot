# db.py
import os

import psycopg2
from psycopg2.extras import Json

DATABASE_URL = os.getenv("DATABASE_URL")


def get_conn():
    """
    Crea y retorna una conexión simple a la base de datos.
    En producción se recomienda usar un pool (por ejemplo psycopg2.pool o asyncpg).
    """
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(DATABASE_URL)


def upsert_alert(alert: dict):
    """
    Inserta o actualiza (upsert) una alerta normalizada en la tabla 'alerts'.

    Campos esperados:
      - id (str): identificador canónico único "repo#alert_number"
      - source (str): origen del dato (ej. 'dependabot')
      - created_at (str | None)
      - package (dict)
      - severity (str)
      - cvss (float | None)
      - cve (list | None)
      - description (str | None)
      - location (dict | None)
      - raw (dict)
    """
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                sql = """
                INSERT INTO alerts (
                    id,
                    repo,
                    source,
                    severity,
                    cvss,
                    cve,
                    description,
                    package,
                    location,
                    created_at,
                    normalized,
                    raw,
                    ingested_at,
                    last_seen_at,
                    status
                )
                VALUES (
                    %(id)s,
                    %(repo)s,
                    %(source)s,
                    %(severity)s,
                    %(cvss)s,
                    %(cve)s,
                    %(description)s,
                    %(package)s,
                    %(location)s,
                    %(created_at)s,
                    %(normalized)s,
                    %(raw)s,
                    now(),
                    now(),
                    'open'
                )
                ON CONFLICT (id) DO UPDATE SET
                    normalized = EXCLUDED.normalized,
                    raw = EXCLUDED.raw,
                    last_seen_at = now(),
                    severity = EXCLUDED.severity,
                    cvss = EXCLUDED.cvss,
                    cve = EXCLUDED.cve,
                    description = EXCLUDED.description,
                    package = EXCLUDED.package,
                    location = EXCLUDED.location;
                """
                data = {
                    "id": alert["id"],
                    "repo": alert["id"].split("#")[0],
                    "source": alert.get("source", "dependabot"),
                    "severity": alert.get("severity"),
                    "cvss": alert.get("cvss"),
                    "cve": alert.get("cve"),
                    "description": alert.get("description"),
                    "package": Json(alert.get("package", {})),
                    "location": Json(alert.get("location", {})),
                    "created_at": alert.get("created_at"),
                    "normalized": Json(alert),
                    "raw": Json(alert.get("raw", {})),
                }
                cur.execute(sql, data)
    finally:
        conn.close()
