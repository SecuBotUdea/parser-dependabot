# secubot/mapper.py
from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel
from typing import Literal


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
    created_at: Optional[str] = None
    package: PackageInfo
    severity: str
    cvss: Optional[float] = None
    cve: Optional[List[str]] = None
    description: Optional[str] = None
    location: Optional[Location] = None
    raw: Any


# ----------------- Helpers -----------------
def _normalize_severity(s: Optional[str]) -> str:
    if not s:
        return "unknown"
    s_l = s.strip().lower()
    if s_l in {"critical", "high", "medium", "low"}:
        return s_l
    return "unknown"


def _extract_cves(security_advisory: Dict[str, Any]) -> Optional[List[str]]:
    if not security_advisory:
        return None
    ids = []

    # identifiers: list of {value, type}
    identifiers = security_advisory.get("identifiers")
    if isinstance(identifiers, list):
        for ident in identifiers:
            if not isinstance(ident, dict):
                continue
            val = ident.get("value")
            typ = (ident.get("type") or "").upper()
            if val and (typ == "CVE" or val.startswith("CVE-")):
                ids.append(val)

    # fallback common single fields
    if not ids:
        cve_id = security_advisory.get("cve_id") or security_advisory.get("cve")
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            ids.append(cve_id)

    return ids or None


def _extract_cvss(security_advisory: Dict[str, Any]) -> Optional[float]:
    if not security_advisory:
        return None

    # Prefer cvss_v4.score inside cvss_severities
    cvss_sev = security_advisory.get("cvss_severities") or {}
    if isinstance(cvss_sev, dict):
        cvss_v4 = cvss_sev.get("cvss_v4") or {}
        score = cvss_v4.get("score")
        if isinstance(score, (int, float)):
            return float(score)

        cvss_v3 = cvss_sev.get("cvss_v3") or {}
        score3 = cvss_v3.get("score")
        if isinstance(score3, (int, float)):
            return float(score3)

    # fallback to security_advisory.cvss.score
    cvss_obj = security_advisory.get("cvss")
    if isinstance(cvss_obj, dict):
        score = cvss_obj.get("score")
        if isinstance(score, (int, float)):
            return float(score)

    return None


def _first_patched_version(security_advisory: Dict[str, Any]) -> Optional[str]:
    if not security_advisory:
        return None

    # vulnerabilities: list -> first_patched_version.identifier
    vulns = security_advisory.get("vulnerabilities")
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            fp = v.get("first_patched_version")
            if isinstance(fp, dict) and fp.get("identifier"):
                return fp.get("identifier")

    # fallback to security_advisory.first_patched_version (rare)
    fp_top = security_advisory.get("first_patched_version")
    if isinstance(fp_top, dict) and fp_top.get("identifier"):
        return fp_top.get("identifier")

    return None


def _iso_or_none(timestr: Optional[str]) -> Optional[str]:
    if not timestr:
        return None
    try:
        # fromisoformat accepts offset-aware strings; replace Z
        dt = datetime.fromisoformat(timestr.replace("Z", "+00:00"))
        return dt.isoformat()
    except Exception:
        # No strong parsing: try common RFC formats
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(timestr, fmt)
                return dt.isoformat()
            except Exception:
                continue
    # If parsing fails, return original string (still useful) or None
    return timestr


# ----------------- Mapper principal -----------------
def map_dependabot_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map a Dependabot webhook payload into the canonical AlertModel dict.
    Deterministic: only derives values from the raw payload (no assignments / owners).
    """
    alert = raw_payload.get("alert", {}) or {}
    repo = raw_payload.get("repository", {}) or {}
    security_advisory = alert.get("security_advisory", {}) or {}
    security_vulnerability = alert.get("security_vulnerability", {}) or {}

    # canonical id: repo_full#alert_number
    repo_full = repo.get("full_name") or raw_payload.get("repository_full_name") or "unknown/repo"
    alert_number = alert.get("number") or raw_payload.get("id") or "unknown"
    canonical_id = f"{repo_full}#{alert_number}"

    # package: prefer alert.dependency.package, fallback to security_vulnerability.package
    dep = alert.get("dependency", {}) or {}
    dep_pkg = dep.get("package") if isinstance(dep, dict) else None
    if not dep_pkg:
        # fallback to security_vulnerability.package
        dep_pkg = security_vulnerability.get("package") if isinstance(security_vulnerability.get("package"), dict) else {}

    pkg_name = (dep_pkg.get("name") if isinstance(dep_pkg, dict) else None) or ""
    pkg_eco = (dep_pkg.get("ecosystem") if isinstance(dep_pkg, dict) else None) or ""

    # current_version: try dependency.version then security_vulnerability.vulnerable_version_range then "unknown"
    current_version = ""
    if isinstance(dep, dict):
        current_version = dep.get("version") or ""
    if not current_version:
        # security_vulnerability.vulnerable_version_range is common
        current_version = security_vulnerability.get("vulnerable_version_range") or ""
    if not current_version:
        current_version = "unknown"

    # fixed_version: try advisory vulnerabilities first, then security_vulnerability.first_patched_version
    fixed_version = _first_patched_version(security_advisory)
    if not fixed_version and isinstance(security_vulnerability.get("first_patched_version"), dict):
        fixed_version = security_vulnerability.get("first_patched_version", {}).get("identifier")

    package_obj = {
        "name": pkg_name,
        "ecosystem": pkg_eco,
        "current_version": current_version,
        "fixed_version": fixed_version,
    }

    # created_at normalization: prefer alert.created_at then top-level created_at
    created_at_raw = alert.get("created_at") or raw_payload.get("created_at")
    created_at_iso = _iso_or_none(created_at_raw)

    # severity normalization
    severity = _normalize_severity(
        security_advisory.get("severity") or alert.get("severity") or security_vulnerability.get("severity")
    )

    # cvss & cve
    cvss_score = _extract_cvss(security_advisory)
    cve_list = _extract_cves(security_advisory)

    # description: prefer advisory.summary then advisory.description then alert.description
    description = (
        security_advisory.get("summary")
        or security_advisory.get("description")
        or alert.get("description")
    )

    # location: manifest_path from alert.dependency or alert.manifest_path
    manifest_path = None
    if isinstance(alert.get("dependency"), dict):
        manifest_path = alert.get("dependency", {}).get("manifest_path")
    if not manifest_path:
        manifest_path = alert.get("manifest_path")

    location_obj = None
    if manifest_path:
        location_obj = {
            "file": manifest_path,
            "path": f"{repo_full}/{manifest_path}",
            "line": None,
        }

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

    # validate with Pydantic and return canonical dict
    validated = AlertModel(**obj)
    return validated.dict()
