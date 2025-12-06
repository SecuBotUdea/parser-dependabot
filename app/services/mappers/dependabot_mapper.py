import hashlib
from datetime import datetime
from typing import Any, Dict

from app.models.alert_model import Alert


class DependabotMapper:
    """
    Mapper para transformar datos del webhook de Dependabot al modelo Alert.
    """

    # Constantes de mapeo
    SEVERITY_MAP = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }

    @staticmethod
    def map_to_alert(webhook_data: Dict[str, Any]) -> Alert:
        """
        Mapea la estructura del webhook de Dependabot al modelo Alert.

        Args:
            webhook_data: Datos completos del webhook de Dependabot

        Returns:
            Alert con los datos mapeados
        """
        alert_data = webhook_data.get("alert", {})
        repository = webhook_data.get("repository", {})
        security_advisory = alert_data.get("security_advisory", {})
        dependency = alert_data.get("dependency", {})

        # Generar signature única basada en CVE/GHSA + repo + paquete
        signature = DependabotMapper._generate_signature(
            security_advisory, repository, dependency
        )

        # Extraer severidad normalizada
        severity = DependabotMapper._extract_severity(security_advisory)

        # Generar normalized_payload
        normalized_payload = {
            "cve_id": security_advisory.get("cve_id"),
            "ghsa_id": security_advisory.get("ghsa_id"),
            "cvss_score": DependabotMapper._extract_cvss_score(security_advisory),
            "description": security_advisory.get("summary", ""),
            "package": {
                "name": dependency.get("package", {}).get("name", "unknown"),
                "ecosystem": dependency.get("package", {}).get("ecosystem", "unknown"),
            },
            "manifest_path": dependency.get("manifest_path", ""),
            "vulnerable_version_range": security_advisory.get("vulnerabilities", [{}])[
                0
            ].get("vulnerable_version_range", ""),
            "patched_version": security_advisory.get("vulnerabilities", [{}])[0]
            .get("first_patched_version", {})
            .get("identifier", ""),
            "references": [
                ref.get("url") for ref in security_advisory.get("references", [])
            ],
            "cwes": [cwe.get("cwe_id") for cwe in security_advisory.get("cwes", [])],
        }

        # Crear lifecycle history entry inicial
        lifecycle_history = [
            {
                "timestamp": alert_data.get(
                    "created_at", datetime.utcnow().isoformat()
                ),
                "status": "open",
                "action": "created",
                "actor": "dependabot",
            }
        ]

        return Alert(
            alert_id=DependabotMapper._generate_alert_id(repository, alert_data),
            signature=signature,
            source_id="dependabot",
            severity=severity,
            component=dependency.get("package", {}).get("name", "unknown"),
            status=alert_data.get("state", "open"),
            first_seen=DependabotMapper._parse_datetime(alert_data.get("created_at")),
            last_seen=DependabotMapper._parse_datetime(alert_data.get("updated_at")),
            quality="high",  # Dependabot siempre tiene buena calidad
            normalized_payload=normalized_payload,
            lifecycle_history=lifecycle_history,
            reopen_count=0,
            last_reopened_at=None,
            version=1,
        )

    @staticmethod
    def _generate_signature(
        security_advisory: Dict[str, Any],
        repository: Dict[str, Any],
        dependency: Dict[str, Any],
    ) -> str:
        """
        Genera una firma única para identificar la alerta.
        Basada en: CVE/GHSA + repo + paquete
        """
        cve_id = security_advisory.get("cve_id") or security_advisory.get(
            "ghsa_id", "unknown"
        )
        repo_name = repository.get("full_name", "unknown")
        package_name = dependency.get("package", {}).get("name", "unknown")

        signature_string = f"{cve_id}:{repo_name}:{package_name}"
        return hashlib.sha256(signature_string.encode()).hexdigest()[:16]

    @staticmethod
    def _extract_cvss_score(security_advisory: Dict[str, Any]) -> float:
        """Extrae el CVSS score del security advisory."""
        # Priorizar CVSS v4, luego v3
        cvss_severities = security_advisory.get("cvss_severities", {})

        cvss_v4 = cvss_severities.get("cvss_v4", {})
        if cvss_v4.get("score", 0.0) > 0:
            return cvss_v4.get("score", 0.0)

        cvss_v3 = cvss_severities.get("cvss_v3", {})
        if cvss_v3.get("score", 0.0) > 0:
            return cvss_v3.get("score", 0.0)

        # Fallback al campo cvss legacy
        cvss_data = security_advisory.get("cvss", {})
        return cvss_data.get("score", 0.0)

    @staticmethod
    def _extract_severity(security_advisory: Dict[str, Any]) -> str:
        """
        Extrae la severidad como texto normalizado.
        """
        severity_text = security_advisory.get("severity", "medium").lower()
        return DependabotMapper.SEVERITY_MAP.get(severity_text, "medium")

    @staticmethod
    def _generate_alert_id(
        repository: Dict[str, Any], alert_data: Dict[str, Any]
    ) -> str:
        """
        Genera un ID único basado en el repositorio y el número de alert.
        Formato: dependabot-{owner}-{repo}-{number}
        """
        repo_full_name = repository.get("full_name", "unknown-repo")
        alert_number = alert_data.get("number", "unknown")

        # Reemplazar caracteres especiales
        repo_safe = repo_full_name.replace("/", "-").lower()

        return f"dependabot-{repo_safe}-{alert_number}"

    @staticmethod
    def _parse_datetime(dt_string: str) -> datetime:
        """Parsea una fecha ISO 8601 a datetime."""
        if not dt_string:
            return datetime.utcnow()

        try:
            # Manejar formato con Z
            if dt_string.endswith("Z"):
                dt_string = dt_string[:-1] + "+00:00"
            return datetime.fromisoformat(dt_string)
        except (ValueError, AttributeError):
            return datetime.utcnow()
