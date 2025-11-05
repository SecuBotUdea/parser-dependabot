from typing import Dict

from db.connection import get_conn
from psycopg2.extras import Json

from app.models.alert_model import AlertModel

UPSERT_SQL = """
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


class AlertRepository:
    def __init__(self):
        pass

    def upsert_alert(self, alert_payload: Dict):
        """
        Valida con AlertModel y persiste en la BD.
        """
        alert = AlertModel(**alert_payload)  # valida/normaliza
        data = {
            "id": alert.id,
            "repo": alert.id.split("#")[0],
            "source": alert.source,
            "severity": alert.severity,
            "cvss": alert.cvss,
            "cve": alert.cve,
            "description": alert.description,
            "package": Json(alert.package or {}),
            "location": Json(alert.location or {}),
            "created_at": alert.created_at,
            "normalized": Json(alert.dict()),
            "raw": Json(alert.raw or {}),
        }

        # usar el context manager del connection pool
        with get_conn() as conn:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(UPSERT_SQL, data)
