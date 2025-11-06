from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.routes.items import get_alert_service


@patch("app.routes.items.get_alert_service.AlertService")
@patch("app.routes.items.get_alert_service.AlertRepository")
@patch("app.routes.items.get_alert_service.get_supabase")
def test_get_alert_service_success(mock_get_supabase, mock_repo, mock_service):
    """Debe devolver una instancia de AlertService correctamente."""
    mock_supabase = MagicMock(name="SupabaseClientMock")
    mock_repo_instance = MagicMock(name="AlertRepositoryMock")
    mock_service_instance = MagicMock(name="AlertServiceMock")

    mock_get_supabase.return_value = mock_supabase
    mock_repo.return_value = mock_repo_instance
    mock_service.return_value = mock_service_instance

    result = get_alert_service.get_alert_service()

    # Se devuelva la instancia de servicio
    assert result == mock_service_instance

    # Verifica llamadas en orden
    mock_get_supabase.assert_called_once()
    mock_repo.assert_called_once_with(mock_supabase)
    mock_service.assert_called_once_with(mock_repo_instance)


@patch("app.routes.items.get_alert_service.get_supabase")
def test_get_alert_service_failure(mock_get_supabase):
    """Debe lanzar HTTPException(500) si get_supabase falla."""
    mock_get_supabase.side_effect = Exception("DB connection failed")

    try:
        get_alert_service.get_alert_service()
    except HTTPException as e:
        assert e.status_code == 500
        assert "Database dependency failed" in e.detail
    else:
        assert False, "Debió lanzar HTTPException"
