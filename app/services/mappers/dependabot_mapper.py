import hashlib
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from app.models.alert_model import Alert, AlertSeverity, AlertSource, AlertStatus


class DependabotMapper:
    """
    Convierte un objeto `alert` de Dependabot al modelo canónico `Alert`.
    Entrada esperada: solo el contenido de la alerta, no el webhook completo.
    """

    SEVERITY_MAP = {
        "informational": AlertSeverity.informational,
        "low": AlertSeverity.low,
        "medium": AlertSeverity.medium,
        "high": AlertSeverity.high,
        "critical": AlertSeverity.critical,
    }

    STATUS_MAP = {
        "open": AlertStatus.open,
        "fixed": AlertStatus.fixed,
        "dismissed": AlertStatus.dismissed,
        "resolved": AlertStatus.resolved,
    }

    @staticmethod
    def map_to_alert(alert_data: Dict[str, Any]) -> Alert:
        dependency = alert_data.get("dependency", {})
        security_advisory = alert_data.get("security_advisory", {})
        security_vulnerability = alert_data.get("security_vulnerability", {})

        package = dependency.get("package", {})
        package_name = package.get("name", "unknown")
        ecosystem = package.get("ecosystem", "unknown")

        created_at = DependabotMapper._parse_datetime(alert_data.get("created_at"))
        updated_at = DependabotMapper._parse_datetime(alert_data.get("updated_at"))

        source_id = str(alert_data.get("number", "unknown"))
        alert_id = DependabotMapper._generate_alert_id(alert_data)

        severity = DependabotMapper._extract_severity(
            security_advisory, security_vulnerability
        )
        status = DependabotMapper._extract_status(alert_data)
        external_references_score = DependabotMapper._extract_cvss_score(security_advisory)

        location = alert_data.get("html_url")

        title = security_advisory.get("summary") or f"Dependabot alert for {package_name}"

        normalized_payload = {
            "source": "dependabot",
            "number": alert_data.get("number"),
            "state": alert_data.get("state", "unknown"),
            "title": title,
            "cve_id": security_advisory.get("cve_id"),
            "ghsa_id": security_advisory.get("ghsa_id"),
            "cvss_score": DependabotMapper._extract_cvss_score(security_advisory),
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
            "manifest_path": dependency.get("manifest_path"),
            "scope": dependency.get("scope"),
            "vulnerable_version_range": DependabotMapper._extract_vulnerable_version_range(
                security_advisory, security_vulnerability
            ),
            "patched_version": DependabotMapper._extract_patched_version(
                security_advisory, security_vulnerability
            ),
            "references": [
                ref.get("url")
                for ref in security_advisory.get("references", [])
                if ref.get("url")
            ],
            "identifiers": [
                {
                    "type": item.get("type"),
                    "value": item.get("value"),
                }
                for item in security_advisory.get("identifiers", [])
                if item.get("type") and item.get("value")
            ],
        }

        lifecycle_history = [
            {
                "timestamp": created_at.isoformat(),
                "status": status.value,
                "action": "created",
                "actor": "dependabot",
            }
        ]

        return Alert(
            alert_id=alert_id,
            source_type=AlertSource.dependabot,
            source_id=source_id,
            title=title,
            severity=severity,
            external_references_score=external_references_score,
            status=status,
            component=package_name,
            location=location,
            first_seen=created_at,
            last_seen=updated_at,
            normalized_payload=normalized_payload,
            raw_payload=alert_data,
            lifecycle_history=lifecycle_history,
            reopen_count=0,
            version=1,
        )

    @staticmethod
    def _generate_alert_id(alert_data: Dict[str, Any]) -> str:
        html_url = alert_data.get("html_url")
        number = alert_data.get("number", "unknown")

        if html_url:
            parsed = urlparse(html_url)
            parts = [part for part in parsed.path.split("/") if part]

            # Esperado: /OWNER/REPO/security/dependabot/NUMBER
            if len(parts) >= 2:
                repo = f"{parts[0]}-{parts[1]}".lower()
                return f"dependabot-{repo}-{number}"

            digest = hashlib.sha256(html_url.encode("utf-8")).hexdigest()[:16]
            return f"dependabot-{digest}-{number}"

        return f"dependabot-unknown-{number}"

    @staticmethod
    def _extract_status(alert_data: Dict[str, Any]) -> AlertStatus:
        state = str(alert_data.get("state", "unknown")).lower()
        return DependabotMapper.STATUS_MAP.get(state, AlertStatus.unknown)

    @staticmethod
    def _extract_severity(
        security_advisory: Dict[str, Any],
        security_vulnerability: Dict[str, Any],
    ) -> AlertSeverity:
        raw_severity = (
            security_advisory.get("severity")
            or security_vulnerability.get("severity")
            or "unknown"
        )
        return DependabotMapper.SEVERITY_MAP.get(
            str(raw_severity).lower(),
            AlertSeverity.unknown,
        )

    @staticmethod
    def _extract_cvss_score(security_advisory: Dict[str, Any]) -> Optional[float]:
        cvss_severities = security_advisory.get("cvss_severities", {})

        for key in ("cvss_v4", "cvss_v3"):
            score = cvss_severities.get(key, {}).get("score")
            if isinstance(score, (int, float)) and score > 0:
                return float(score)

        score = security_advisory.get("cvss", {}).get("score")
        if isinstance(score, (int, float)) and score > 0:
            return float(score)

        return None

    @staticmethod
    def _extract_vulnerable_version_range(
        security_advisory: Dict[str, Any],
        security_vulnerability: Dict[str, Any],
    ) -> Optional[str]:
        vulnerabilities = security_advisory.get("vulnerabilities", [])
        if vulnerabilities:
            value = vulnerabilities[0].get("vulnerable_version_range")
            if value:
                return value

        value = security_vulnerability.get("vulnerable_version_range")
        return value or None

    @staticmethod
    def _extract_patched_version(
        security_advisory: Dict[str, Any],
        security_vulnerability: Dict[str, Any],
    ) -> Optional[str]:
        vulnerabilities = security_advisory.get("vulnerabilities", [])
        if vulnerabilities:
            patched = vulnerabilities[0].get("first_patched_version", {})
            identifier = patched.get("identifier")
            if identifier:
                return identifier

        patched = security_vulnerability.get("first_patched_version", {})
        identifier = patched.get("identifier")
        return identifier or None

    @staticmethod
    def _parse_datetime(dt_string: Optional[str]) -> datetime:
        if not dt_string:
            return datetime.utcnow()

        try:
            if dt_string.endswith("Z"):
                dt_string = dt_string[:-1] + "+00:00"
            return datetime.fromisoformat(dt_string)
        except (ValueError, AttributeError):
            return datetime.utcnow()
