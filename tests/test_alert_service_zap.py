from unittest.mock import Mock

import pytest

from app.services.alert_service import AlertService


@pytest.fixture
def mock_repository():
    """Mock del repositorio."""
    return Mock()


@pytest.fixture
def alert_service(mock_repository):
    """Instancia de AlertService con repositorio mockeado."""
    return AlertService(alert_repository=mock_repository)


@pytest.fixture
def complete_zap_report():
    """Fixture con un reporte completo de OWASP ZAP."""
    return {
        "@programName": "ZAP",
        "@version": "2.16.1",
        "@generated": "2025-12-05T22:10:29",
        "site": [
            {
                "@name": "https://test-app.com",
                "@host": "test-app.com",
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
                        "wascid": "32",
                        "instances": [
                            {
                                "uri": "https://test-app.com/api",
                                "method": "POST",
                                "param": "",
                                "attack": "test",
                                "evidence": "error",
                            }
                        ],
                        "count": "1",
                    },
                    {
                        "pluginid": "10038",
                        "alertRef": "10038-1",
                        "alert": "Content Security Policy Not Set",
                        "riskcode": "2",
                        "confidence": "3",
                        "desc": "CSP header missing",
                        "solution": "Set CSP header",
                        "cweid": "693",
                        "wascid": "15",
                        "instances": [
                            {
                                "uri": "https://test-app.com/",
                                "method": "GET",
                            }
                        ],
                        "count": "1",
                    },
                ],
            }
        ],
    }


@pytest.mark.service
def test_create_alert_from_zap(alert_service, mock_repository, complete_zap_report):
    """Crea alertas desde un reporte de OWASP ZAP."""
    # Arrange
    mock_alert_1 = Mock(id="test-app-com-zap-40048", cve="CWE-78", severity=7.5)
    mock_alert_2 = Mock(id="test-app-com-zap-10038", cve="CWE-693", severity=5.0)
    mock_repository.upsert.side_effect = [mock_alert_1, mock_alert_2]

    # Act
    result = alert_service.create_alert_from_zap(complete_zap_report)

    # Assert
    assert len(result) == 2
    assert mock_repository.upsert.call_count == 2
    assert result[0].id == "test-app-com-zap-40048"
    assert result[0].severity == 7.5
    assert result[1].id == "test-app-com-zap-10038"
    assert result[1].severity == 5.0


@pytest.mark.service
def test_create_alert_from_zap_single_alert(alert_service, mock_repository):
    """Crea una sola alerta desde un reporte ZAP."""
    # Arrange
    zap_report = {
        "@version": "2.16.1",
        "@generated": "2025-12-05T22:10:29",
        "site": [
            {
                "@name": "https://example.com",
                "alerts": [
                    {
                        "pluginid": "99999",
                        "alert": "Test Vulnerability",
                        "riskcode": "3",
                        "cweid": "123",
                        "desc": "Test description",
                        "instances": [],
                        "count": "1",
                    }
                ],
            }
        ],
    }
    mock_alert = Mock(id="example-com-zap-99999", cve="CWE-123")
    mock_repository.upsert.return_value = mock_alert

    # Act
    result = alert_service.create_alert_from_zap(zap_report)

    # Assert
    assert len(result) == 1
    mock_repository.upsert.assert_called_once()
    assert result[0].id == "example-com-zap-99999"


@pytest.mark.service
def test_create_alert_from_zap_empty_report(alert_service, mock_repository):
    """Maneja correctamente un reporte ZAP sin alertas."""
    # Arrange
    empty_report = {
        "@version": "2.16.1",
        "@generated": "2025-12-05T22:10:29",
        "site": [{"@name": "https://example.com", "alerts": []}],
    }

    # Act
    result = alert_service.create_alert_from_zap(empty_report)

    # Assert
    assert len(result) == 0
    mock_repository.upsert.assert_not_called()


@pytest.mark.service
def test_create_alert_from_dependabot(alert_service, mock_repository):
    """Crea un alert desde webhook de Dependabot."""
    # Arrange
    dependabot_webhook = {
        "alert": {
            "number": 1,
            "created_at": "2025-12-05T22:10:29Z",
            "security_advisory": {
                "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
                "cve_id": "CVE-2025-58754",
                "severity": "high",
                "cvss": {"score": 7.5},
                "summary": "Test vulnerability",
            },
            "dependency": {
                "package": {"name": "test-package", "ecosystem": "npm"},
                "manifest_path": "package.json",
            },
        },
        "repository": {"full_name": "test/repo"},
    }
    mock_repository.upsert.return_value = Mock(id="test-id", cve="CVE-2025-58754")

    # Act
    result = alert_service.create_alert_from_dependabot(dependabot_webhook)

    # Assert
    mock_repository.upsert.assert_called_once()
    assert result.id == "test-id"


@pytest.mark.service
def test_get_alert_by_id(alert_service, mock_repository):
    """Obtiene un alert por ID."""
    # Arrange
    mock_alert = Mock(id="test-123", cve="CVE-2024-0001")
    mock_repository.get_by_id.return_value = mock_alert

    # Act
    result = alert_service.get_alert("test-123")

    # Assert
    mock_repository.get_by_id.assert_called_once_with("test-123")
    assert result.id == "test-123"


@pytest.mark.service
def test_get_alert_returns_none_when_not_found(alert_service, mock_repository):
    """Retorna None cuando el alert no existe."""
    # Arrange
    mock_repository.get_by_id.return_value = None

    # Act
    result = alert_service.get_alert("non-existent")

    # Assert
    assert result is None
