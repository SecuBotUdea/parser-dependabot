import hashlib
from datetime import datetime
from typing import Any, Dict, List

from app.models.alert_model import Alert


class TrivyMapper:
    """
    Mapper para transformar datos del reporte JSON de Trivy SAST al modelo Alert.
    Procesa: Misconfigurations y Secrets.
    """

    # Mapeo de severidad de Trivy a normalizada
    SEVERITY_MAP = {
        "UNKNOWN": "informational",
        "LOW": "low",
        "MEDIUM": "medium",
        "HIGH": "high",
        "CRITICAL": "critical",
    }

    @staticmethod
    def map_to_alerts(trivy_report: Dict[str, Any]) -> List[Alert]:
        """
        Mapea el reporte completo de Trivy SAST a múltiples Alert.

        Args:
            trivy_report: Datos completos del reporte JSON de Trivy

        Returns:
            Lista de Alert con los datos mapeados
        """
        alerts = []
        results = trivy_report.get("Results", [])

        # Metadata del reporte
        scan_date = trivy_report.get("CreatedAt", datetime.utcnow().isoformat())
        artifact_name = trivy_report.get("ArtifactName", "unknown")
        artifact_type = trivy_report.get("ArtifactType", "unknown")
        metadata = trivy_report.get("Metadata", {})

        for result in results:
            target = result.get("Target", "unknown")

            # Procesar misconfigurations
            misconfigs = result.get("Misconfigurations", [])
            for misconfig in misconfigs:
                alert = TrivyMapper._map_misconfiguration(
                    misconfig, target, artifact_name, artifact_type, metadata, scan_date
                )
                alerts.append(alert)

            # Procesar secrets
            secrets = result.get("Secrets", [])
            for secret in secrets:
                alert = TrivyMapper._map_secret(
                    secret, target, artifact_name, artifact_type, metadata, scan_date
                )
                alerts.append(alert)

        return alerts

    @staticmethod
    def _map_misconfiguration(
        misconfig: Dict[str, Any],
        target: str,
        artifact_name: str,
        artifact_type: str,
        metadata: Dict[str, Any],
        scan_date: str,
    ) -> Alert:
        """Mapea una misconfiguration de Trivy al modelo Alert."""

        misconfig_id = misconfig.get("ID", "unknown")
        avd_id = misconfig.get("AVDID", "")
        title = misconfig.get("Title", "Unknown Misconfiguration")
        severity = misconfig.get("Severity", "MEDIUM")
        misconfig_type = misconfig.get("Type", "")

        # Generar signature única
        signature = TrivyMapper._generate_signature(
            artifact_name, target, misconfig_id, "misconfig"
        )

        # Extraer metadata de causa
        cause_metadata = misconfig.get("CauseMetadata", {})
        code_info = TrivyMapper._extract_code_info(cause_metadata)

        # Normalized payload
        normalized_payload = {
            "type": "misconfiguration",
            "misconfig_id": misconfig_id,
            "avd_id": avd_id,
            "title": title,
            "description": misconfig.get("Description", ""),
            "message": misconfig.get("Message", ""),
            "resolution": misconfig.get("Resolution", ""),
            "primary_url": misconfig.get("PrimaryURL", ""),
            "references": misconfig.get("References", []),
            "status": misconfig.get("Status", "FAIL"),
            "namespace": misconfig.get("Namespace", ""),
            "query": misconfig.get("Query", ""),
            "check_type": misconfig_type,
            "provider": cause_metadata.get("Provider", ""),
            "service": cause_metadata.get("Service", ""),
            "start_line": cause_metadata.get("StartLine"),
            "end_line": cause_metadata.get("EndLine"),
            "code": code_info,
            "target_file": target,
            "artifact_name": artifact_name,
            "artifact_type": artifact_type,
            "repo_url": metadata.get("RepoURL", ""),
            "branch": metadata.get("Branch", ""),
            "commit": metadata.get("Commit", ""),
            "commit_msg": metadata.get("CommitMsg", ""),
            "author": metadata.get("Author", ""),
        }

        # Lifecycle history
        lifecycle_history = [
            {
                "timestamp": scan_date,
                "status": "open",
                "action": "detected",
                "actor": "trivy_sast",
                "details": f"Misconfiguration {misconfig_id} detected in {target}",
            }
        ]

        # Generate alert_id
        alert_id = TrivyMapper._generate_alert_id(artifact_name, target, misconfig_id)

        # Component: target file
        component = target

        return Alert(
            alert_id=alert_id,
            signature=signature,
            source_id=f"trivy-misconfig-{misconfig_id}",
            severity=TrivyMapper.SEVERITY_MAP.get(severity, "medium"),
            component=component,
            status="open",
            first_seen=TrivyMapper._parse_datetime(scan_date),
            last_seen=TrivyMapper._parse_datetime(scan_date),
            quality="medium",
            normalized_payload=normalized_payload,
            lifecycle_history=lifecycle_history,
            reopen_count=0,
            last_reopened_at=None,
            version=1,
        )

    @staticmethod
    def _map_secret(
        secret: Dict[str, Any],
        target: str,
        artifact_name: str,
        artifact_type: str,
        metadata: Dict[str, Any],
        scan_date: str,
    ) -> Alert:
        """Mapea un secret de Trivy al modelo Alert."""

        rule_id = secret.get("RuleID", "unknown")
        category = secret.get("Category", "")
        title = secret.get("Title", "Secret Detected")
        severity = secret.get("Severity", "HIGH")

        # Generar signature única
        signature = TrivyMapper._generate_signature(
            artifact_name, target, rule_id, "secret"
        )

        # Extraer código
        code_info = TrivyMapper._extract_code_info_from_secret(secret.get("Code", {}))

        # Normalized payload
        normalized_payload = {
            "type": "secret",
            "rule_id": rule_id,
            "category": category,
            "title": title,
            "start_line": secret.get("StartLine"),
            "end_line": secret.get("EndLine"),
            "match": secret.get("Match", ""),
            "code": code_info,
            "target_file": target,
            "artifact_name": artifact_name,
            "artifact_type": artifact_type,
            "repo_url": metadata.get("RepoURL", ""),
            "branch": metadata.get("Branch", ""),
            "commit": metadata.get("Commit", ""),
            "commit_msg": metadata.get("CommitMsg", ""),
            "author": metadata.get("Author", ""),
        }

        # Lifecycle history
        lifecycle_history = [
            {
                "timestamp": scan_date,
                "status": "open",
                "action": "detected",
                "actor": "trivy_sast",
                "details": f"Secret {category} detected in {target}",
            }
        ]

        # Generate alert_id
        alert_id = TrivyMapper._generate_alert_id(artifact_name, target, rule_id)

        # Component: target file
        component = target

        return Alert(
            alert_id=alert_id,
            signature=signature,
            source_id=f"trivy-secret-{rule_id}",
            severity=TrivyMapper.SEVERITY_MAP.get(severity, "high"),
            component=component,
            status="open",
            first_seen=TrivyMapper._parse_datetime(scan_date),
            last_seen=TrivyMapper._parse_datetime(scan_date),
            quality="high",  # Secrets son alta prioridad
            normalized_payload=normalized_payload,
            lifecycle_history=lifecycle_history,
            reopen_count=0,
            last_reopened_at=None,
            version=1,
        )

    @staticmethod
    def _extract_code_info(cause_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrae información del código desde CauseMetadata."""
        code = cause_metadata.get("Code", {})
        lines = code.get("Lines", [])

        return [
            {
                "number": line.get("Number"),
                "content": line.get("Content", ""),
                "is_cause": line.get("IsCause", False),
                "annotation": line.get("Annotation", ""),
                "highlighted": line.get("Highlighted", ""),
                "first_cause": line.get("FirstCause", False),
                "last_cause": line.get("LastCause", False),
            }
            for line in lines
        ]

    @staticmethod
    def _extract_code_info_from_secret(code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrae información del código desde secret Code."""
        lines = code.get("Lines", [])

        return [
            {
                "number": line.get("Number"),
                "content": line.get("Content", ""),
                "is_cause": line.get("IsCause", False),
                "annotation": line.get("Annotation", ""),
                "highlighted": line.get("Highlighted", ""),
                "first_cause": line.get("FirstCause", False),
                "last_cause": line.get("LastCause", False),
            }
            for line in lines
        ]

    @staticmethod
    def _generate_signature(
        artifact_name: str, target: str, finding_id: str, finding_type: str
    ) -> str:
        """Genera una firma única para la alerta."""
        signature_string = f"{artifact_name}:{target}:{finding_id}:{finding_type}"
        return hashlib.sha256(signature_string.encode()).hexdigest()[:16]

    @staticmethod
    def _generate_alert_id(artifact_name: str, target: str, finding_id: str) -> str:
        """Genera un ID único para la alerta."""
        # Limpiar nombres
        artifact_safe = artifact_name.replace("/", "-").replace(".", "-").lower()
        target_safe = target.replace("/", "-").replace(".", "-").lower()

        return f"trivy-{artifact_safe}-{target_safe}-{finding_id}"

    @staticmethod
    def _parse_datetime(dt_string: str) -> datetime:
        """Parsea una fecha ISO 8601 a datetime."""
        if not dt_string:
            return datetime.utcnow()

        try:
            if dt_string.endswith("Z"):
                dt_string = dt_string[:-1] + "+00:00"
            return datetime.fromisoformat(dt_string.split(".")[0])
        except (ValueError, AttributeError):
            return datetime.utcnow()
