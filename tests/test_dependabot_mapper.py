import pytest
from app.services.mappers.dependabot_mapper import DependabotMapper
from app.models.alert_model import AlertModel


@pytest.mark.mapper
def test_map_to_alert_complete_data(complete_webhook):
    """Mapea datos completos correctamente desde archivo fixture."""
    result = DependabotMapper.map_to_alert(complete_webhook)
    
    assert isinstance(result, AlertModel), "Debe retornar un AlertModel"
    assert result.id == "pangoaguirre-meeting-doc-generator-alert-11"
    assert result.repo == "PangoAguirre/meeting-doc-generator"
    assert result.source == "dependabot"
    assert result.severity == 7.5
    assert result.cvss == 7.5
    assert result.cve == "CVE-2025-58754"
    assert result.package["name"] == "axios"
    assert result.package["ecosystem"] == "npm"


@pytest.mark.mapper
def test_map_webhook_without_cve(webhook_no_cve):
    """Mapea webhook sin CVE, usa GHSA como fallback."""
    result = DependabotMapper.map_to_alert(webhook_no_cve)
    
    assert result.cve.startswith("GHSA-"), f"Debe usar GHSA ID: {result.cve}"


@pytest.mark.mapper
def test_map_minimal_webhook(webhook_minimal):
    """Mapea webhook con datos mínimos, usa defaults."""
    result = DependabotMapper.map_to_alert(webhook_minimal)
    
    assert result is not None
    assert result.source == "dependabot"
    # Verifica que los defaults se aplicaron correctamente


@pytest.mark.mapper
def test_extract_cvss_score_present():
    """Extrae CVSS score cuando está presente."""
    security_advisory = {"cvss": {"score": 8.5}}
    result = DependabotMapper._extract_cvss_score(security_advisory)
    assert result == 8.5


@pytest.mark.mapper
def test_extract_cvss_score_missing():
    """Retorna 0.0 cuando no hay CVSS score."""
    security_advisory = {}
    result = DependabotMapper._extract_cvss_score(security_advisory)
    assert result == 0.0


@pytest.mark.mapper
@pytest.mark.parametrize("severity_text,expected_score", [
    ("low", 3.0),
    ("medium", 5.0),
    ("high", 7.5),
    ("critical", 9.0),
    ("unknown", 5.0)  # default
])
def test_extract_severity_mapping(severity_text, expected_score):
    """Mapea correctamente diferentes niveles de severidad."""
    security_advisory = {
        "severity": severity_text,
        "cvss": {"score": 0.0}
    }
    result = DependabotMapper._extract_severity(security_advisory)
    assert result == expected_score


@pytest.mark.mapper
def test_extract_severity_prefers_cvss():
    """Prioriza CVSS score sobre texto de severidad."""
    security_advisory = {
        "severity": "low",
        "cvss": {"score": 9.0}
    }
    result = DependabotMapper._extract_severity(security_advisory)
    assert result == 9.0


@pytest.mark.mapper
@pytest.mark.parametrize("advisory,expected", [
    ({"cve_id": "CVE-2024-0001", "ghsa_id": "GHSA-xxxx"}, "CVE-2024-0001"),
    ({"ghsa_id": "GHSA-xxxx-yyyy"}, "GHSA-xxxx-yyyy"),
    ({}, "N/A")
])
def test_extract_cve_id(advisory, expected):
    """Extrae CVE ID con diferentes casos."""
    result = DependabotMapper._extract_cve_id(advisory)
    assert result == expected


@pytest.mark.mapper
@pytest.mark.parametrize("advisory,expected", [
    ({"summary": "Short", "description": "Long"}, "Short"),
    ({"description": "Long"}, "Long"),
    ({}, "")
])
def test_extract_description(advisory, expected):
    """Extrae descripción con diferentes casos."""
    result = DependabotMapper._extract_description(advisory)
    assert result == expected


@pytest.mark.mapper
def test_extract_package_info():
    """Extrae información del paquete."""
    dependency = {
        "package": {
            "name": "lodash",
            "ecosystem": "npm"
        }
    }
    result = DependabotMapper._extract_package_info(dependency)
    assert result["name"] == "lodash"
    assert result["ecosystem"] == "npm"


@pytest.mark.mapper
def test_extract_package_info_defaults():
    """Usa defaults cuando faltan datos."""
    result = DependabotMapper._extract_package_info({})
    assert result["name"] == "unknown"
    assert result["ecosystem"] == "unknown"


@pytest.mark.mapper
def test_extract_location_info():
    """Extrae información de ubicación."""
    dependency = {
        "manifest_path": "src/package.json",
        "scope": "runtime",
        "relationship": "direct"
    }
    result = DependabotMapper._extract_location_info(dependency)
    assert result["manifest_path"] == "src/package.json"
    assert result["scope"] == "runtime"
    assert result["relationship"] == "direct"


@pytest.mark.mapper
@pytest.mark.parametrize("repo_name,alert_num,expected", [
    ("Owner/Repo", 42, "owner-repo-alert-42"),
    ("Owner-Org/Repo.Name", 99, "owner-org-repo.name-alert-99"),
    ("UPPERCASE/repo", 1, "uppercase-repo-alert-1")
])
def test_generate_alert_id(repo_name, alert_num, expected):
    """Genera IDs correctos con diferentes formatos."""
    repository = {"full_name": repo_name}
    alert_data = {"number": alert_num}
    result = DependabotMapper._generate_alert_id(repository, alert_data)
    assert result == expected


@pytest.mark.mapper
def test_map_preserves_raw_data(complete_webhook):
    """Preserva datos raw completos."""
    result = DependabotMapper.map_to_alert(complete_webhook)
    assert result.raw == complete_webhook
    assert result.raw["action"] == "created"
