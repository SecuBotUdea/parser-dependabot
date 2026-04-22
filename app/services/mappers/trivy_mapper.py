from datetime import datetime
from typing import Any, Dict, List

from app.models.alert_model import Alert, AlertSeverity, AlertSource, AlertStatus


class TrivyMapper:
    """
    Mapper para transformar datos del reporte JSON de Trivy SAST al modelo Alert.
    Procesa: Misconfigurations y Secrets.
    """

    SEVERITY_MAP = {
        "UNKNOWN": AlertSeverity.informational,
        "LOW": AlertSeverity.low,
        "MEDIUM": AlertSeverity.medium,
        "HIGH": AlertSeverity.high,
        "CRITICAL": AlertSeverity.critical,
    }

    @staticmethod
    def map_to_alerts(trivy_report: Dict[str, Any]) -> List[Alert]:
        alerts = []
        results = trivy_report.get("Results", [])

        scan_date = trivy_report.get("CreatedAt", datetime.utcnow().isoformat())
        artifact_name = trivy_report.get("ArtifactName", "unknown")
        artifact_type = trivy_report.get("ArtifactType", "unknown")
        metadata = trivy_report.get("Metadata", {})

        for result in results:
            target = result.get("Target", "unknown")

            for misconfig in result.get("Misconfigurations", []):
                alert = TrivyMapper._map_misconfiguration(
                    misconfig,
                    target,
                    artifact_name,
                    artifact_type,
                    metadata,
                    scan_date,
                    trivy_report,
                )
                alerts.append(alert)

            for secret in result.get("Secrets", []):
                alert = TrivyMapper._map_secret(
                    secret,
                    target,
                    artifact_name,
                    artifact_type,
                    metadata,
                    scan_date,
                    trivy_report,
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
        raw_report: Dict[str, Any],
    ) -> Alert:
        misconfig_id = misconfig.get("ID", "unknown")
        title = misconfig.get("Title", "Unknown Misconfiguration")
        severity = misconfig.get("Severity", "UNKNOWN")
        cause_metadata = misconfig.get("CauseMetadata", {})
        code_info = TrivyMapper._extract_code_info(cause_metadata)
        primary_url = misconfig.get("PrimaryURL", "") or None

        normalized_payload = {
            "type": "misconfiguration",
            "misconfig_id": misconfig_id,
            "avd_id": misconfig.get("AVDID", ""),
            "title": title,
            "description": misconfig.get("Description", ""),
            "message": misconfig.get("Message", ""),
            "resolution": misconfig.get("Resolution", ""),
            "primary_url": primary_url,
            "references": misconfig.get("References", []),
            "status": misconfig.get("Status", "FAIL"),
            "namespace": misconfig.get("Namespace", ""),
            "query": misconfig.get("Query", ""),
            "check_type": misconfig.get("Type", ""),
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

        lifecycle_history = [
            {
                "timestamp": scan_date,
                "status": AlertStatus.open.value,
                "action": "detected",
                "actor": "trivy_sast",
                "details": f"Misconfiguration {misconfig_id} detected in {target}",
            }
        ]

        parsed_date = TrivyMapper._parse_datetime(scan_date)

        return Alert(
            alert_id=TrivyMapper._generate_alert_id(
                artifact_name, target, misconfig_id
            ),
            source_type=AlertSource.trivy,
            source_id=f"trivy-misconfig-{misconfig_id}",
            title=title,
            severity=TrivyMapper.SEVERITY_MAP.get(severity, AlertSeverity.unknown),
            status=AlertStatus.open,
            component=target,
            location=primary_url,
            first_seen=parsed_date,
            last_seen=parsed_date,
            normalized_payload=normalized_payload,
            raw_payload=raw_report,
            lifecycle_history=lifecycle_history,
            reopen_count=0,
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
        raw_report: Dict[str, Any],
    ) -> Alert:
        rule_id = secret.get("RuleID", "unknown")
        category = secret.get("Category", "")
        title = secret.get("Title", "Secret Detected")
        severity = secret.get("Severity", "HIGH")
        code_info = TrivyMapper._extract_code_info_from_secret(secret.get("Code", {}))

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

        lifecycle_history = [
            {
                "timestamp": scan_date,
                "status": AlertStatus.open.value,
                "action": "detected",
                "actor": "trivy_sast",
                "details": f"Secret {category} detected in {target}",
            }
        ]

        parsed_date = TrivyMapper._parse_datetime(scan_date)

        return Alert(
            alert_id=TrivyMapper._generate_alert_id(artifact_name, target, rule_id),
            source_type=AlertSource.trivy,
            source_id=f"trivy-secret-{rule_id}",
            title=title,
            severity=TrivyMapper.SEVERITY_MAP.get(severity, AlertSeverity.unknown),
            status=AlertStatus.open,
            component=target,
            location=None,
            first_seen=parsed_date,
            last_seen=parsed_date,
            normalized_payload=normalized_payload,
            raw_payload=raw_report,
            lifecycle_history=lifecycle_history,
            reopen_count=0,
            version=1,
        )

    @staticmethod
    def _extract_code_info(cause_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        lines = cause_metadata.get("Code", {}).get("Lines", [])
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
    def _generate_alert_id(artifact_name: str, target: str, finding_id: str) -> str:
        artifact_safe = artifact_name.replace("/", "-").replace(".", "-").lower()
        target_safe = target.replace("/", "-").replace(".", "-").lower()
        return f"trivy-{artifact_safe}-{target_safe}-{finding_id}"

    @staticmethod
    def _parse_datetime(dt_string: str) -> datetime:
        if not dt_string:
            return datetime.utcnow()
        try:
            if dt_string.endswith("Z"):
                dt_string = dt_string[:-1] + "+00:00"
            return datetime.fromisoformat(dt_string.split(".")[0])
        except (ValueError, AttributeError):
            return datetime.utcnow()
