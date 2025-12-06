import hashlib
from datetime import datetime
from typing import Any, Dict, List

from app.models.alert_model import Alert


class ZapMapper:
    """
    Mapper para transformar datos del reporte JSON de OWASP ZAP al modelo Alert.
    """

    # Mapeo de riskcode de ZAP a severidad normalizada
    RISK_MAP = {
        "0": "informational",
        "1": "low",
        "2": "medium",
        "3": "high",
    }

    # Mapeo de confidence de ZAP
    CONFIDENCE_MAP = {
        "0": "false_positive",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "confirmed",
    }

    @staticmethod
    def map_to_alerts(zap_report: Dict[str, Any]) -> List[Alert]:
        """
        Mapea el reporte completo de OWASP ZAP a múltiples Alert.

        Args:
            zap_report: Datos completos del reporte JSON de OWASP ZAP

        Returns:
            Lista de Alert con los datos mapeados
        """
        alerts = []
        sites = zap_report.get("site", [])

        # Metadata del reporte
        scan_date = zap_report.get("@generated", datetime.utcnow().isoformat())
        zap_version = zap_report.get("@version", "unknown")

        for site in sites:
            site_url = site.get("@name", "unknown")
            site_alerts = site.get("alerts", [])

            for alert_data in site_alerts:
                alert = ZapMapper._map_single_alert(
                    alert_data, site_url, scan_date, zap_version
                )
                alerts.append(alert)

        return alerts

    @staticmethod
    def _map_single_alert(
        alert_data: Dict[str, Any],
        site_url: str,
        scan_date: str,
        zap_version: str,
    ) -> Alert:
        """
        Mapea una alerta individual de ZAP al modelo Alert.
        """
        plugin_id = alert_data.get("pluginid", "unknown")
        alert_name = alert_data.get("alert", "Unknown Alert")
        riskcode = str(alert_data.get("riskcode", "2"))
        confidence = str(alert_data.get("confidence", "2"))

        # Generar signature única
        signature = ZapMapper._generate_signature(site_url, plugin_id, alert_name)

        # Extraer severidad normalizada
        severity = ZapMapper.RISK_MAP.get(riskcode, "medium")

        # Determinar quality basado en confidence
        quality = ZapMapper._determine_quality(confidence)

        # Generar normalized_payload
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

        # Crear lifecycle history entry inicial
        lifecycle_history = [
            {
                "timestamp": scan_date,
                "status": "open",
                "action": "detected",
                "actor": "owasp_zap",
            }
        ]

        # Generar alert_id único
        alert_id = ZapMapper._generate_alert_id(site_url, plugin_id)

        return Alert(
            alert_id=alert_id,
            signature=signature,
            source_id="zap",
            severity=severity,
            component=ZapMapper._extract_component(site_url, alert_data),
            status="open",
            first_seen=ZapMapper._parse_datetime(scan_date),
            last_seen=ZapMapper._parse_datetime(scan_date),
            quality=quality,
            normalized_payload=normalized_payload,
            lifecycle_history=lifecycle_history,
            reopen_count=0,
            last_reopened_at=None,
            version=1,
        )

    @staticmethod
    def _generate_signature(site_url: str, plugin_id: str, alert_name: str) -> str:
        """
        Genera una firma única para identificar la alerta.
        Basada en: site_url + plugin_id + alert_name
        """
        domain = ZapMapper._extract_domain(site_url)
        signature_string = f"{domain}:{plugin_id}:{alert_name}"
        return hashlib.sha256(signature_string.encode()).hexdigest()[:16]

    @staticmethod
    def _determine_quality(confidence: str) -> str:
        """
        Determina la calidad basada en el nivel de confianza de ZAP.
        """
        confidence_map = {
            "0": "low",  # False Positive
            "1": "low",  # Low confidence
            "2": "medium",  # Medium confidence
            "3": "high",  # High confidence
            "4": "high",  # Confirmed
        }
        return confidence_map.get(confidence, "medium")

    @staticmethod
    def _extract_component(site_url: str, alert_data: Dict[str, Any]) -> str:
        """
        Extrae el componente afectado.
        Para ZAP, usamos el dominio + tipo de vulnerabilidad.
        """
        domain = ZapMapper._extract_domain(site_url)
        alert_name = alert_data.get("alert", "unknown")
        return f"{domain}/{alert_name}"

    @staticmethod
    def _extract_instances(instances: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        Extrae y normaliza las instancias de la vulnerabilidad.
        """
        normalized_instances = []

        for instance in instances[:10]:  # Limitar a 10 instancias
            normalized_instances.append(
                {
                    "uri": instance.get("uri", ""),
                    "method": instance.get("method", ""),
                    "param": instance.get("param", ""),
                    "attack": instance.get("attack", ""),
                    "evidence": instance.get("evidence", ""),
                }
            )

        return normalized_instances

    @staticmethod
    def _extract_domain(site_url: str) -> str:
        """
        Extrae el dominio del URL escaneado.
        """
        try:
            # Remover protocolo
            clean_url = site_url.replace("https://", "").replace("http://", "")
            # Tomar solo el dominio (antes del primer /)
            domain = clean_url.split("/")[0]
            # Remover puerto si existe
            domain = domain.split(":")[0]
            return domain
        except Exception:
            return "unknown"

    @staticmethod
    def _clean_html(text: str) -> str:
        """
        Limpia tags HTML básicos del texto.
        """
        if not text:
            return ""

        # Remover tags HTML comunes
        text = text.replace("<p>", "").replace("</p>", "\n")
        text = text.replace("<br>", "\n").replace("<br/>", "\n")
        text = text.replace("<strong>", "").replace("</strong>", "")
        text = text.replace("<em>", "").replace("</em>", "")

        return text.strip()

    @staticmethod
    def _generate_alert_id(site_url: str, plugin_id: str) -> str:
        """
        Genera un ID único para la alerta.
        Formato: zap-{domain}-{plugin_id}
        """
        domain = ZapMapper._extract_domain(site_url)
        domain_safe = domain.replace(".", "-").replace(":", "-").lower()

        return f"zap-{domain_safe}-{plugin_id}"

    @staticmethod
    def _parse_datetime(dt_string: str) -> datetime:
        """Parsea una fecha de ZAP a datetime."""
        if not dt_string:
            return datetime.utcnow()

        try:
            # ZAP usa formato: "Fri, 5 Dec 2025 22:10:29"
            # O formato ISO: "2025-12-05T22:10:29"
            if "T" in dt_string:
                # Formato ISO
                if dt_string.endswith("Z"):
                    dt_string = dt_string[:-1] + "+00:00"
                return datetime.fromisoformat(dt_string.split(".")[0])
            else:
                # Formato de ZAP con día de semana
                # Remover el día de la semana si existe
                parts = dt_string.split(", ")
                if len(parts) > 1:
                    dt_string = parts[1]
                return datetime.strptime(dt_string, "%d %b %Y %H:%M:%S")
        except (ValueError, AttributeError):
            return datetime.utcnow()
