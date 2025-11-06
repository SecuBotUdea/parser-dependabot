import pytest
from unittest.mock import Mock
from app.services.alert_service import AlertService
from app.models.alert_model import AlertModel


@pytest.fixture
def mock_repository():
    """Mock del repositorio."""
    return Mock()


@pytest.fixture
def alert_service(mock_repository):
    """Instancia de AlertService con repositorio mockeado."""
    return AlertService(alert_repository=mock_repository)


@pytest.mark.service
def test_create_alert_from_dependabot(alert_service, mock_repository, complete_webhook):
    """Crea un alert desde webhook de Dependabot."""
    # Arrange
    mock_repository.upsert.return_value = Mock(id="test-id", cve="CVE-2025-58754")
    
    # Act
    result = alert_service.create_alert_from_dependabot(complete_webhook)
    
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