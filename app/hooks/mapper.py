from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel


# ================== MODELOS BASE ==================
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
    """
    Representa una alerta normalizada independiente de la fuente (SAST, SCA, DAST...).
    """

    id: str
    source: Literal["dependabot"] = "dependabot"
    created_at: Optional[str] = None
    package: PackageInfo
    severity: str
    cvss: Optional[float] = None
    cve: Optional[List[str]] = None
    description: Optional[str] = None
    location: Optional[Location] = None
    raw: Any


# ================== HELPERS ==================
def _normalize_severity(s: Optional[str]) -> str:
    """
    Devuelve severidad normalizada entre: critical | high | medium | low | unknown
    """
    if not s:
        return "unknown"
    s_l = s.strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",  # algunos advisories usan "moderate"
        "low": "low",
        "info": "low",  # opcional: tratar info como low
    }
    return mapping.get(s_l, "unknown")


def _extract_cves(security_advisory: Dict[str, Any]) -> Optional[List[str]]:
    """
    Extrae lista de identificadores CVE desde los campos más comunes del advisory.
    """
    if not security_advisory:
        return None
    ids = []

    identifiers = security_advisory.get("identifiers")
    if isinstance(identifiers, list):
        for ident in identifiers:
            if not isinstance(ident, dict):
                continue
            val = ident.get("value")
            typ = (ident.get("type") or "").upper()
            if val and (typ == "CVE" or val.startswith("CVE-")):
                ids.append(val)

    if not ids:
        cve_id = security_advisory.get("cve_id") or security_advisory.get("cve")
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            ids.append(cve_id)

    return ids or None


def _extract_cvss(security_advisory: Dict[str, Any]) -> Optional[float]:
    """
    Extrae puntaje CVSS preferiblemente de cvss_v4 o cvss_v3, o de cvss.score.
    """
    if not security_advisory:
        return None

    cvss_sev = security_advisory.get("cvss_severities") or {}
    if isinstance(cvss_sev, dict):
        for key in ("cvss_v4", "cvss_v3"):
            cvss_x = cvss_sev.get(key) or {}
            score = cvss_x.get("score")
            if isinstance(score, (int, float)):
                return float(score)

    cvss_obj = security_advisory.get("cvss")
    if isinstance(cvss_obj, dict):
        score = cvss_obj.get("score")
        if isinstance(score, (int, float)):
            return float(score)

    return None


def _first_patched_version(security_advisory: Dict[str, Any]) -> Optional[str]:
    """
    Devuelve la primera versión parcheada si está disponible.
    """
    if not security_advisory:
        return None

    vulns = security_advisory.get("vulnerabilities")
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            fp = v.get("first_patched_version")
            if isinstance(fp, dict) and fp.get("identifier"):
                return fp["identifier"]

    fp_top = security_advisory.get("first_patched_version")
    if isinstance(fp_top, dict) and fp_top.get("identifier"):
        return fp_top["identifier"]

    return None


def _iso_or_none(timestr: Optional[str]) -> Optional[str]:
    """
    Intenta convertir una fecha a ISO 8601; si falla, devuelve el string original.
    """
    if not timestr:
        return None
    try:
        dt = datetime.fromisoformat(timestr.replace("Z", "+00:00"))
        return dt.isoformat()
    except Exception:
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(timestr, fmt)
                return dt.isoformat()
            except Exception:
                continue
    # fallback: retornar string sin modificar para mantener trazabilidad
    return timestr


# ================== MAPPER PRINCIPAL ==================
def map_dependabot_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convierte un payload de Dependabot en el formato común AlertModel.
    Determinista y sin efectos colaterales (solo normaliza información).
    """
    alert = raw_payload.get("alert", {}) or {}
    repo = raw_payload.get("repository", {}) or {}
    security_advisory = alert.get("security_advisory", {}) or {}
    security_vulnerability = alert.get("security_vulnerability", {}) or {}

    # Canonical ID: <repo_full>#<alert_number>
    repo_full = (
        repo.get("full_name")
        or raw_payload.get("repository_full_name")
        or "unknown/repo"
    )
    alert_number = alert.get("number") or raw_payload.get("id") or "unknown"
    canonical_id = f"{repo_full}#{alert_number}"

    # -------- PACKAGE INFO --------
    dep = alert.get("dependency", {}) or {}
    dep_pkg = dep.get("package") if isinstance(dep, dict) else None
    if not dep_pkg:
        dep_pkg = (
            security_vulnerability.get("package")
            if isinstance(security_vulnerability.get("package"), dict)
            else {}
        )

    pkg_name = (dep_pkg.get("name") if isinstance(dep_pkg, dict) else "") or ""
    pkg_eco = (dep_pkg.get("ecosystem") if isinstance(dep_pkg, dict) else "") or ""

    current_version = ""
    if isinstance(dep, dict):
        current_version = dep.get("version") or ""
    if not current_version:
        current_version = security_vulnerability.get("vulnerable_version_range") or ""
    if not current_version:
        current_version = "unknown"

    fixed_version = _first_patched_version(security_advisory)
    if not fixed_version and isinstance(
        security_vulnerability.get("first_patched_version"), dict
    ):
        fixed_version = security_vulnerability.get("first_patched_version", {}).get(
            "identifier"
        )

    package_obj = {
        "name": pkg_name,
        "ecosystem": pkg_eco,
        "current_version": current_version,
        "fixed_version": fixed_version,
    }

    # -------- TIMESTAMP, SEVERITY, CVSS, CVE --------
    created_at_raw = alert.get("created_at") or raw_payload.get("created_at")
    created_at_iso = _iso_or_none(created_at_raw)

    severity = _normalize_severity(
        security_advisory.get("severity")
        or alert.get("severity")
        or security_vulnerability.get("severity")
    )

    cvss_score = _extract_cvss(security_advisory)
    cve_list = _extract_cves(security_advisory)

    description = (
        security_advisory.get("summary")
        or security_advisory.get("description")
        or alert.get("description")
    )

    # -------- LOCATION --------
    manifest_path = None
    if isinstance(alert.get("dependency"), dict):
        manifest_path = alert["dependency"].get("manifest_path")
    if not manifest_path:
        manifest_path = alert.get("manifest_path")

    location_obj = None
    if manifest_path:
        location_obj = {
            "file": manifest_path,
            "path": f"{repo_full}/{manifest_path}",
            "line": None,
        }

    # -------- FINAL OBJETO --------
    obj = {
        "id": canonical_id,
        "created_at": created_at_iso,
        "package": package_obj,
        "severity": severity,
        "cvss": cvss_score,
        "cve": cve_list,
        "description": description,
        "location": location_obj,
        "raw": raw_payload,
    }

    validated = AlertModel(**obj)
    return validated.dict()
