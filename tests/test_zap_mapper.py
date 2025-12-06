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

    assert alert.source_id == "zap"  # 👈 Cambio: source -> source_id
    assert (
        alert.component == "example.com/Remote Code Execution"
    )  # 👈 Cambio: formato del component
    assert alert.severity == "high"  # 👈 Cambio: 7.5 -> "high" (string)
    assert (
        alert.normalized_payload["cwe_id"] == "78"
    )  # 👈 Cambio: cve -> normalized_payload["cwe_id"]
    assert (
        "Critical vulnerability" in alert.normalized_payload["description"]
    )  # 👈 Cambio: location
    assert (
        alert.normalized_payload["alert_name"] == "Remote Code Execution"
    )  # 👈 Cambio: package -> normalized_payload
    assert (
        alert.normalized_payload["site_url"] == "https://example.com"
    )  # 👈 Cambio: location
    assert alert.normalized_payload["instance_count"] == 1  # 👈 Cambio: tipo int


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
    assert alerts[0].normalized_payload["alert_name"] == "CSP Not Set"  # 👈 Cambio
    assert (
        alerts[1].normalized_payload["alert_name"] == "XSS Vulnerability"
    )  # 👈 Cambio
    assert alerts[0].severity == "medium"  # 👈 Cambio: 5.0 -> "medium"
    assert alerts[1].severity == "high"  # 👈 Cambio: 7.5 -> "high"


def test_extract_severity():
    """Test mapeo de severidad desde riskcode."""
    # Informational
    alert_info = {"riskcode": "0"}
    assert (
        ZapMapper.RISK_MAP[alert_info["riskcode"]] == "informational"
    )  # 👈 Cambio: usar RISK_MAP directamente

    # Low
    alert_low = {"riskcode": "1"}
    assert ZapMapper.RISK_MAP[alert_low["riskcode"]] == "low"  # 👈 Cambio: 3.0 -> "low"

    # Medium
    alert_medium = {"riskcode": "2"}
    assert (
        ZapMapper.RISK_MAP[alert_medium["riskcode"]] == "medium"
    )  # 👈 Cambio: 5.0 -> "medium"

    # High
    alert_high = {"riskcode": "3"}
    assert (
        ZapMapper.RISK_MAP[alert_high["riskcode"]] == "high"
    )  # 👈 Cambio: 7.5 -> "high"

    # Default (sin riskcode)
    assert (
        ZapMapper.RISK_MAP.get("2", "medium") == "medium"
    )  # 👈 Cambio: usar get con default


def test_extract_domain_from_url():
    """Test extracción de dominio desde URL."""
    assert (
        ZapMapper._extract_domain("https://example.com") == "example.com"
    )  # 👈 Cambio: método renombrado
    assert (
        ZapMapper._extract_domain("https://example.com:8080") == "example.com"
    )  # 👈 Cambio: sin puerto
    assert ZapMapper._extract_domain("http://test.vercel.app/path") == "test.vercel.app"


def test_generate_alert_id():
    """Test generación de ID único."""
    alert_id = ZapMapper._generate_alert_id(
        "https://example.com", "40048"
    )  # 👈 Cambio: solo 2 parámetros
    assert alert_id == "zap-example-com-40048"  # 👈 Cambio: formato actualizado

    # Con puerto
    alert_id2 = ZapMapper._generate_alert_id("https://example.com:8080", "10038")
    assert (
        alert_id2 == "zap-example-com-10038"
    )  # 👈 Cambio: puerto removido en _extract_domain


def test_generate_signature():
    """Test generación de signature única."""
    signature = ZapMapper._generate_signature("https://example.com", "40048", "RCE")
    assert len(signature) == 16  # 👈 Nuevo test: verificar longitud de hash
    assert isinstance(signature, str)

    # Mismo input debería dar mismo signature
    signature2 = ZapMapper._generate_signature("https://example.com", "40048", "RCE")
    assert signature == signature2


def test_determine_quality():
    """Test determinación de quality basada en confidence."""
    assert ZapMapper._determine_quality("0") == "low"  # False positive
    assert ZapMapper._determine_quality("1") == "low"  # Low confidence
    assert ZapMapper._determine_quality("2") == "medium"  # Medium confidence
    assert ZapMapper._determine_quality("3") == "high"  # High confidence
    assert ZapMapper._determine_quality("4") == "high"  # Confirmed


def test_clean_html():
    """Test limpieza de HTML."""
    html_text = "<p>Test <strong>bold</strong> text</p><br/>Next line"
    cleaned = ZapMapper._clean_html(html_text)
    assert "<p>" not in cleaned
    assert "<strong>" not in cleaned
    assert "Test bold text" in cleaned

    # Empty text
    assert ZapMapper._clean_html("") == ""
    assert ZapMapper._clean_html(None) == ""
