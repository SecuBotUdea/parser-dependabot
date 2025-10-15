from pydantic import BaseModel
from typing import Literal
from typing import Optional, List, Any

class PackageInfo(BaseModel):
    name: str
    ecosystem: str
    current_version: str
    fixed_version: Optional[str] = None

class Location(BaseModel):
    file: Optional[str] = None
    path: Optional[str] = None
    line: Optional[int] = None

class AlertModel(BaseModel):
    id: str
    source: Literal["dependabot"] = "dependabot"
    created_at: str
    package: PackageInfo
    severity: str
    cvss: Optional[float] = None
    cve: Optional[List[str]] = None
    description: Optional[str] = None
    location: Optional[Location] = None
    raw: Any

def map_dependabot_payload(raw_payload: dict) -> dict:
    """
    Mapea un payload de Dependabot -> formato canónico.
    Este es un mapeo base; lo adaptaremos si tu payload real tiene campos distintos.
    """
        # Intentamos obtener un número/id de alerta conocido
    alert_number = (
        raw_payload.get("alert", {}).get("number")
            or raw_payload.get("id")
            or raw_payload.get("dependency", {}).get("package", {}).get("name")
            or "unknown"
        )
    repo_full = raw_payload.get("repository", {}).get("full_name", "unknown/repo")
    id_canonical = f"{repo_full}#{alert_number}"

    package = {
            "name": raw_payload.get("dependency", {}).get("package", {}).get("name", "") or "",
            "ecosystem": raw_payload.get("dependency", {}).get("package", {}).get("ecosystem", "") or "",
            "current_version": raw_payload.get("dependency", {}).get("version", "") or "",
            "fixed_version": None
        }

    obj = {
            "id": id_canonical,
            "created_at": raw_payload.get("created_at") or raw_payload.get("alert", {}).get("created_at") or None,
            "package": package,
            "severity": raw_payload.get("security_advisory", {}).get("severity") or raw_payload.get("alert", {}).get("severity") or "unknown",
            "cvss": raw_payload.get("security_advisory", {}).get("cvss", None),
            "cve": raw_payload.get("security_advisory", {}).get("identifiers", {}).get("CVE", None),
            "description": raw_payload.get("security_advisory", {}).get("summary") or raw_payload.get("alert", {}).get("description"),
            "location": None,
            "raw": raw_payload
        }

        # Validación con Pydantic
    validated = AlertModel(**obj)
    return validated.dict()