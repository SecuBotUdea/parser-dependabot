import pytest

from app.core.config import get_supabase
from app.repositories.alert_repo import AlertRepository
from app.services.alert_service import AlertService


@pytest.fixture
def alert_service_real():
    """AlertService con repositorio real."""
    supabase = get_supabase()
    return AlertService(AlertRepository(supabase))


@pytest.fixture
def complete_zap_report():
    """Fixture con un reporte completo de OWASP ZAP."""
    return {
        "@programName": "ZAP",
        "@version": "2.16.1",
        "@generated": "2025-12-05T22:10:29",
        "site": [
            {
                "@name": "https://integration-test.com",
                "@host": "integration-test.com",
                "@port": "443",
                "@ssl": "true",
                "alerts": [
                    {
                        "pluginid": "40048",
                        "alertRef": "40048",
                        "alert": "Remote Code Execution (Test)",
                        "riskcode": "3",
                        "confidence": "3",
                        "desc": "Test vulnerability for integration",
                        "solution": "Update dependencies",
                        "cweid": "78",
                        "wascid": "32",
                        "instances": [
                            {
                                "uri": "https://integration-test.com/api",
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
                        "alert": "CSP Not Set (Test)",
                        "riskcode": "2",
                        "confidence": "3",
                        "desc": "CSP header missing",
                        "solution": "Set CSP header",
                        "cweid": "693",
                        "wascid": "15",
                        "instances": [
                            {
                                "uri": "https://integration-test.com/",
                                "method": "GET",
                            }
                        ],
                        "count": "2",
                    },
                ],
            }
        ],
    }


@pytest.mark.integration
def test_create_alerts_from_zap(alert_service_real, complete_zap_report):
    """Crea múltiples alertas desde ZAP (integración)."""
    # Create
    created_alerts = alert_service_real.create_alert_from_zap(complete_zap_report)

    assert len(created_alerts) == 2
    assert created_alerts[0].alert_id is not None
    assert created_alerts[1].alert_id is not None
    assert created_alerts[0].source_id == "zap"
    assert created_alerts[1].source_id == "zap"

    # Verificar severidades (riskcode 3 = high, riskcode 2 = medium)
    assert created_alerts[0].severity == "high"  # 👈 riskcode "3" = "high"
    assert created_alerts[1].severity == "medium"  # 👈 riskcode "2" = "medium"

    # Cleanup
    for alert in created_alerts:
        alert_service_real.alert_repository.supabase.table("alert").delete().eq(
            "alert_id", alert.alert_id
        ).execute()


@pytest.mark.integration
def test_upsert_zap_alert_updates_existing(alert_service_real):
    """Verifica que upsert actualiza alertas existentes de ZAP (integración)."""
    # Arrange: crear alerta inicial
    initial_report = {
        "@version": "2.16.1",
        "@generated": "2025-12-05T22:10:29",
        "site": [
            {
                "@name": "https://upsert-test.com",
                "alerts": [
                    {
                        "pluginid": "99999",
                        "alert": "Upsert Test Alert",
                        "riskcode": "2",
                        "cweid": "123",
                        "desc": "Initial description",
                        "instances": [],
                        "count": "1",
                    }
                ],
            }
        ],
    }

    # Create inicial
    first_alerts = alert_service_real.create_alert_from_zap(initial_report)
    first_alert = first_alerts[0]
    first_alert_id = first_alert.alert_id

    assert first_alert.severity == "medium"  # riskcode "2" = "medium"
    assert "Initial description" in first_alert.normalized_payload.get(
        "description", ""
    )

    # Act: actualizar con misma alerta pero diferente severidad
    updated_report = {
        "@version": "2.16.1",
        "@generated": "2025-12-05T23:00:00",
        "site": [
            {
                "@name": "https://upsert-test.com",
                "alerts": [
                    {
                        "pluginid": "99999",
                        "alert": "Upsert Test Alert",
                        "riskcode": "3",  # Cambió de 2 a 3
                        "cweid": "123",
                        "desc": "Updated description",
                        "instances": [],
                        "count": "2",
                    }
                ],
            }
        ],
    }

    updated_alerts = alert_service_real.create_alert_from_zap(updated_report)
    updated_alert = updated_alerts[0]

    # Assert: mismo ID pero datos actualizados
    assert updated_alert.alert_id == first_alert_id
    assert updated_alert.severity == "high"  # Cambió de "medium" a "high"
    assert "Updated description" in updated_alert.normalized_payload.get(
        "description", ""
    )

    # Cleanup
    alert_service_real.alert_repository.supabase.table("alert").delete().eq(
        "alert_id", first_alert_id
    ).execute()
