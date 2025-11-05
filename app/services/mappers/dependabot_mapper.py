from typing import Dict, Any
from datetime import datetime
from app.models.alert_model import AlertModel


class DependabotMapper:
    """
    Mapper para transformar datos del webhook de Dependabot al modelo AlertModel.
    """
    
    # Constantes de mapeo
    SEVERITY_MAP = {
        "low": 3.0,
        "medium": 5.0,
        "high": 7.5,
        "critical": 9.0
    }
    
    @staticmethod
    def map_to_alert(webhook_data: Dict[str, Any]) -> AlertModel:
        """
        Mapea la estructura del webhook de Dependabot al modelo AlertModel.
        
        Args:
            webhook_data: Datos completos del webhook de Dependabot
            
        Returns:
            AlertModel con los datos mapeados
        """
        alert_data = webhook_data.get("alert", {})
        repository = webhook_data.get("repository", {})
        security_advisory = alert_data.get("security_advisory", {})
        dependency = alert_data.get("dependency", {})
        
        return AlertModel(
            id=DependabotMapper._generate_alert_id(repository, alert_data),
            repo=repository.get("full_name", "unknown"),
            source="dependabot",
            severity=DependabotMapper._extract_severity(security_advisory),
            cvss=DependabotMapper._extract_cvss_score(security_advisory),
            cve=DependabotMapper._extract_cve_id(security_advisory),
            description=DependabotMapper._extract_description(security_advisory),
            package=DependabotMapper._extract_package_info(dependency),
            location=DependabotMapper._extract_location_info(dependency),
            raw=webhook_data,
            created_at=alert_data.get("created_at", datetime.utcnow().isoformat())
        )
    
    @staticmethod
    def _extract_cvss_score(security_advisory: Dict[str, Any]) -> float:
        """Extrae el CVSS score del security advisory."""
        cvss_data = security_advisory.get("cvss", {})
        return cvss_data.get("score", 0.0)
    
    @staticmethod
    def _extract_severity(security_advisory: Dict[str, Any]) -> float:
        """
        Extrae la severidad como número.
        Prioriza CVSS score, usa mapeo de texto como fallback.
        """
        cvss_score = DependabotMapper._extract_cvss_score(security_advisory)
        
        if cvss_score > 0:
            return cvss_score
        
        # Fallback: mapear desde texto
        severity_text = security_advisory.get("severity", "medium").lower()
        return DependabotMapper.SEVERITY_MAP.get(severity_text, 5.0)
    
    @staticmethod
    def _extract_cve_id(security_advisory: Dict[str, Any]) -> str:
        """Extrae CVE ID o usa GHSA ID como fallback."""
        return (
            security_advisory.get("cve_id") or 
            security_advisory.get("ghsa_id", "N/A")
        )
    
    @staticmethod
    def _extract_description(security_advisory: Dict[str, Any]) -> str:
        """Extrae la descripción del advisory."""
        return security_advisory.get("summary", security_advisory.get("description", ""))
    
    @staticmethod
    def _extract_package_info(dependency: Dict[str, Any]) -> Dict[str, str]:
        """Extrae información del paquete."""
        package = dependency.get("package", {})
        return {
            "name": package.get("name", "unknown"),
            "ecosystem": package.get("ecosystem", "unknown")
        }
    
    @staticmethod
    def _extract_location_info(dependency: Dict[str, Any]) -> Dict[str, str]:
        """Extrae información de ubicación del dependency."""
        return {
            "manifest_path": dependency.get("manifest_path", ""),
            "scope": dependency.get("scope", ""),
            "relationship": dependency.get("relationship", "")
        }
    
    @staticmethod
    def _generate_alert_id(repository: Dict[str, Any], alert_data: Dict[str, Any]) -> str:
        """
        Genera un ID único basado en el repositorio y el número de alert.
        Formato: {owner}-{repo}-alert-{number}
        """
        repo_full_name = repository.get("full_name", "unknown-repo")
        alert_number = alert_data.get("number", "unknown")
        
        # Reemplazar caracteres especiales
        repo_safe = repo_full_name.replace("/", "-").lower()
        
        return f"{repo_safe}-alert-{alert_number}"
