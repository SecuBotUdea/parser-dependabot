from app.services.mappers.zap_mapper import ZapMapper


def test_map_zap_report_to_alerts():
    """Test que el mapper convierte correctamente un reporte ZAP a AlertModel."""
    # Arrange: reporte ZAP simulado
    zap_report = {
        "@programName": "ZAP",
        "@version": "2.16.1",
        "@generated": "2025-12-05T22:10:29",
        "site": [
            {
                "@name": "https://example.com",
                "@host": "example.com",
                "@port": "443",
                "@ssl": "true",
                "alerts": [
                    {
                        "pluginid": "40048",
                        "alertRef": "40048",
                        "alert": "Remote Code Execution",
                        "riskcode": "3",
                        "confidence": "3",
                        "desc": "Critical vulnerability found",
                        "solution": "Update dependencies",
                        "cweid": "78",
                        "instances": [
                            {
                                "uri": "https://example.com/api",
                                "method": "POST",
                            }
                        ],
                        "count": "1",
                    }
                ],
            }
        ],
    }

    # Act
    alerts = ZapMapper.map_to_alerts(zap_report)

    # Assert
    assert len(alerts) == 1
    alert = alerts[0]

    assert alert.source == "owasp_zap"
    assert alert.repo == "example.com"
    assert alert.severity == 7.5  # High = 7.5
    assert alert.cve == "CWE-78"
    assert "Critical vulnerability" in alert.description
    assert alert.package["name"] == "Remote Code Execution"
    assert alert.location["site"] == "https://example.com"
    assert alert.location["instance_count"] == "1"


def test_map_multiple_alerts():
    """Test que el mapper maneja múltiples alertas correctamente."""
    # Arrange
    zap_report = {
        "@version": "2.16.1",
        "@generated": "2025-12-05T22:10:29",
        "site": [
            {
                "@name": "https://example.com",
                "alerts": [
                    {
                        "pluginid": "10038",
                        "alert": "CSP Not Set",
                        "riskcode": "2",
                        "cweid": "693",
                        "desc": "Missing CSP header",
                        "instances": [],
                        "count": "3",
                    },
                    {
                        "pluginid": "10095",
                        "alert": "XSS Vulnerability",
                        "riskcode": "3",
                        "cweid": "79",
                        "desc": "XSS found",
                        "instances": [],
                        "count": "1",
                    },
                ],
            }
        ],
    }

    # Act
    alerts = ZapMapper.map_to_alerts(zap_report)

    # Assert
    assert len(alerts) == 2
    assert alerts[0].package["name"] == "CSP Not Set"
    assert alerts[1].package["name"] == "XSS Vulnerability"
    assert alerts[0].severity == 5.0  # Medium
    assert alerts[1].severity == 7.5  # High


def test_extract_severity():
    """Test mapeo de severidad desde riskcode."""
    # Low
    alert_low = {"riskcode": "1"}
    assert ZapMapper._extract_severity(alert_low) == 3.0

    # Medium
    alert_medium = {"riskcode": "2"}
    assert ZapMapper._extract_severity(alert_medium) == 5.0

    # High
    alert_high = {"riskcode": "3"}
    assert ZapMapper._extract_severity(alert_high) == 7.5

    # Default (sin riskcode)
    alert_default = {}
    assert ZapMapper._extract_severity(alert_default) == 5.0


def test_extract_repo_from_url():
    """Test extracción de dominio desde URL."""
    assert ZapMapper._extract_repo_from_url("https://example.com") == "example.com"
    assert (
        ZapMapper._extract_repo_from_url("https://example.com:8080")
        == "example.com:8080"
    )
    assert (
        ZapMapper._extract_repo_from_url("http://test.vercel.app/path")
        == "test.vercel.app"
    )


def test_generate_alert_id():
    """Test generación de ID único."""
    alert_id = ZapMapper._generate_alert_id("https://example.com", "40048", "RCE")
    assert alert_id == "example-com-zap-40048"

    # Con puerto
    alert_id2 = ZapMapper._generate_alert_id("https://example.com:8080", "10038", "CSP")
    assert alert_id2 == "example-com-8080-zap-10038"
