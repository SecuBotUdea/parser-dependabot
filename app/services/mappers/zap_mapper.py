from datetime import datetime
from typing import Any, Dict, List

from app.models.alert_model import AlertModel


class ZapMapper:
    """
    Mapper para transformar datos del reporte JSON de OWASP ZAP al modelo AlertModel.
    """

    # Mapeo de riskcode de ZAP a severidad numérica (similar a CVSS)
    RISK_MAP = {
        "0": 1.0,  # Informational
        "1": 3.0,  # Low
        "2": 5.0,  # Medium
        "3": 7.5,  # High
        "4": 9.0,  # Critical (no está en el estándar ZAP pero por si acaso)
    }

    @staticmethod
    def map_to_alerts(zap_report: Dict[str, Any]) -> List[AlertModel]:
        """
        Mapea el reporte completo de OWASP ZAP a múltiples AlertModel.

        Args:
            zap_report: Datos completos del reporte JSON de OWASP ZAP

        Returns:
            Lista de AlertModel con los datos mapeados
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
        full_report: Dict[str, Any],
    ) -> AlertModel:
        """
        Mapea una alerta individual de ZAP al modelo AlertModel.
        """
        plugin_id = alert_data.get("pluginid", "unknown")
        alert_name = alert_data.get("alert", "Unknown Alert")

        # Generar ID único
        alert_id = ZapMapper._generate_alert_id(site_url, plugin_id, alert_name)

        return AlertModel(
            id=alert_id,
            repo=ZapMapper._extract_repo_from_url(site_url),
            source="owasp_zap",
            severity=ZapMapper._extract_severity(alert_data),
            cvss=ZapMapper._extract_severity(
                alert_data
            ),  # ZAP no usa CVSS directamente
            cve=ZapMapper._extract_cve_info(alert_data),
            description=ZapMapper._extract_description(alert_data),
            package=ZapMapper._extract_package_info(alert_data),
            location=ZapMapper._extract_location_info(alert_data, site_url),
            raw={
                "alert": alert_data,
                "site_url": site_url,
                "scan_metadata": {
                    "generated": scan_date,
                    "zap_version": zap_version,
                },
            },
            created_at=scan_date,
        )

    @staticmethod
    def _extract_severity(alert_data: Dict[str, Any]) -> float:
        """
        Extrae la severidad numérica del riskcode de ZAP.
        """
        riskcode = str(alert_data.get("riskcode", "2"))
        return ZapMapper.RISK_MAP.get(riskcode, 5.0)

    @staticmethod
    def _extract_cve_info(alert_data: Dict[str, Any]) -> str:
        """
        Extrae información de CVE/CWE.
        ZAP usa CWE ID principalmente.
        """
        cweid = alert_data.get("cweid", "")
        plugin_id = alert_data.get("pluginid", "")

        if cweid:
            return f"CWE-{cweid}"

        # Usar plugin ID como fallback
        return f"ZAP-{plugin_id}"

    @staticmethod
    def _extract_description(alert_data: Dict[str, Any]) -> str:
        """
        Extrae la descripción completa de la vulnerabilidad.
        """
        desc = alert_data.get("desc", "")
        solution = alert_data.get("solution", "")

        # Limpiar tags HTML si existen
        desc_clean = desc.replace("<p>", "").replace("</p>", "")
        solution_clean = solution.replace("<p>", "").replace("</p>", "")

        full_description = desc_clean
        if solution_clean:
            full_description += f"\n\nSolution: {solution_clean}"

        return full_description

    @staticmethod
    def _extract_package_info(alert_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Extrae información del 'paquete' afectado.
        Para ZAP, esto es más bien el tipo de vulnerabilidad.
        """
        return {
            "name": alert_data.get("alert", "unknown"),
            "ecosystem": "web-application",
            "plugin_id": alert_data.get("pluginid", ""),
            "alert_ref": alert_data.get("alertRef", ""),
        }

    @staticmethod
    def _extract_location_info(
        alert_data: Dict[str, Any], site_url: str
    ) -> Dict[str, Any]:
        """
        Extrae información de ubicación de las instancias de la vulnerabilidad.
        """
        instances = alert_data.get("instances", [])
        count = alert_data.get("count", "0")

        # Extraer URIs únicos
        uris = []
        methods = []
        for instance in instances:
            uri = instance.get("uri", "")
            method = instance.get("method", "")
            if uri:
                uris.append(uri)
            if method:
                methods.append(method)

        return {
            "site": site_url,
            "affected_uris": uris,
            "http_methods": list(set(methods)),
            "instance_count": count,
            "confidence": alert_data.get("confidence", ""),
            "wascid": alert_data.get("wascid", ""),
        }

    @staticmethod
    def _extract_repo_from_url(site_url: str) -> str:
        """
        Extrae un nombre de 'repositorio' del URL escaneado.
        Para aplicaciones web, usamos el dominio.
        """
        try:
            # Remover protocolo
            clean_url = site_url.replace("https://", "").replace("http://", "")
            # Tomar solo el dominio
            domain = clean_url.split("/")[0]
            return domain
        except Exception:
            return "unknown"

    @staticmethod
    def _generate_alert_id(site_url: str, plugin_id: str, alert_name: str) -> str:
        """
        Genera un ID único para la alerta.
        Formato: {domain}-zap-{plugin_id}
        """
        domain = ZapMapper._extract_repo_from_url(site_url)
        domain_safe = domain.replace(".", "-").replace(":", "-").lower()

        return f"{domain_safe}-zap-{plugin_id}"
