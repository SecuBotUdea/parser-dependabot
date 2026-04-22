from datetime import datetime
from typing import Any, Dict, List

from app.models.alert_model import Alert, AlertSeverity, AlertSource, AlertStatus


class ZapMapper:
    RISK_MAP = {
        "0": AlertSeverity.informational,
        "1": AlertSeverity.low,
        "2": AlertSeverity.medium,
        "3": AlertSeverity.high,
    }

    CONFIDENCE_MAP = {
        "0": "false_positive",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "confirmed",
    }

    @staticmethod
    def map_to_alerts(zap_report: Dict[str, Any]) -> List[Alert]:
        alerts = []
        sites = zap_report.get("site", [])

        scan_date = zap_report.get("@generated", datetime.utcnow().isoformat())
        zap_version = zap_report.get("@version", "unknown")

        for site in sites:
            site_url = site.get("@name", "unknown")
            for alert_data in site.get("alerts", []):
                alert = ZapMapper._map_single_alert(
                    alert_data, site_url, scan_date, zap_version, zap_report
                )
                alerts.append(alert)

        return alerts

    @staticmethod
    def _map_single_alert(
        alert_data: Dict[str, Any],
        site_url: str,
        scan_date: str,
        zap_version: str,
        raw_report: Dict[str, Any],
    ) -> Alert:
        plugin_id = alert_data.get("pluginid", "unknown")
        alert_name = alert_data.get("alert", "Unknown Alert")
        riskcode = str(alert_data.get("riskcode", "2"))
        confidence = str(alert_data.get("confidence", "2"))

        normalized_payload = {
            "plugin_id": plugin_id,
            "alert_ref": alert_data.get("alertRef", ""),
            "alert_name": alert_name,
            "riskcode": riskcode,
            "confidence": confidence,
            "confidence_level": ZapMapper.CONFIDENCE_MAP.get(confidence, "medium"),
            "description": ZapMapper._clean_html(alert_data.get("desc", "")),
            "solution": ZapMapper._clean_html(alert_data.get("solution", "")),
            "other_info": ZapMapper._clean_html(alert_data.get("otherinfo", "")),
            "reference": ZapMapper._clean_html(alert_data.get("reference", "")),
            "cwe_id": alert_data.get("cweid", ""),
            "wasc_id": alert_data.get("wascid", ""),
            "instances": ZapMapper._extract_instances(alert_data.get("instances", [])),
            "instance_count": int(alert_data.get("count", "0")),
            "site_url": site_url,
            "zap_version": zap_version,
        }

        lifecycle_history = [
            {
                "timestamp": scan_date,
                "status": AlertStatus.open.value,
                "action": "detected",
                "actor": "owasp_zap",
            }
        ]

        parsed_date = ZapMapper._parse_datetime(scan_date)

        return Alert(
            alert_id=ZapMapper._generate_alert_id(site_url, plugin_id),
            source_type=AlertSource.zap,
            source_id=f"zap-{plugin_id}",
            title=alert_name,
            severity=ZapMapper.RISK_MAP.get(riskcode, AlertSeverity.unknown),
            status=AlertStatus.open,
            component=ZapMapper._extract_component(site_url, alert_data),
            location=site_url,
            first_seen=parsed_date,
            last_seen=parsed_date,
            normalized_payload=normalized_payload,
            raw_payload=raw_report,
            lifecycle_history=lifecycle_history,
            reopen_count=0,
            version=1,
        )

    @staticmethod
    def _generate_alert_id(site_url: str, plugin_id: str) -> str:
        domain = ZapMapper._extract_domain(site_url)
        domain_safe = domain.replace(".", "-").replace(":", "-").lower()
        return f"zap-{domain_safe}-{plugin_id}"

    @staticmethod
    def _extract_component(site_url: str, alert_data: Dict[str, Any]) -> str:
        domain = ZapMapper._extract_domain(site_url)
        alert_name = alert_data.get("alert", "unknown")
        return f"{domain}/{alert_name}"

    @staticmethod
    def _extract_instances(instances: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        return [
            {
                "uri": instance.get("uri", ""),
                "method": instance.get("method", ""),
                "param": instance.get("param", ""),
                "attack": instance.get("attack", ""),
                "evidence": instance.get("evidence", ""),
            }
            for instance in instances[:10]
        ]

    @staticmethod
    def _extract_domain(site_url: str) -> str:
        try:
            clean_url = site_url.replace("https://", "").replace("http://", "")
            domain = clean_url.split("/")[0].split(":")[0]
            return domain
        except Exception:
            return "unknown"

    @staticmethod
    def _clean_html(text: str) -> str:
        if not text:
            return ""
        text = text.replace("<p>", "").replace("</p>", "\n")
        text = text.replace("<br>", "\n").replace("<br/>", "\n")
        text = text.replace("<strong>", "").replace("</strong>", "")
        text = text.replace("<em>", "").replace("</em>", "")
        return text.strip()

    @staticmethod
    def _parse_datetime(dt_string: str) -> datetime:
        if not dt_string:
            return datetime.utcnow()
        try:
            if "T" in dt_string:
                if dt_string.endswith("Z"):
                    dt_string = dt_string[:-1] + "+00:00"
                return datetime.fromisoformat(dt_string.split(".")[0])
            else:
                parts = dt_string.split(", ")
                if len(parts) > 1:
                    dt_string = parts[1]
                return datetime.strptime(dt_string, "%d %b %Y %H:%M:%S")
        except (ValueError, AttributeError):
            return datetime.utcnow()
