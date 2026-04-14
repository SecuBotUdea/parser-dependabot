from datetime import datetime, timezone

import pytest

from app.models.alert_model import Alert, AlertSeverity, AlertSource, AlertStatus
from app.services.mappers.dependabot_mapper import DependabotMapper


# ---------------------------------------------------------------------------
# T-M1 — map_to_alert con payload vacío
# ---------------------------------------------------------------------------

def test_map_to_alert_empty_dict_produces_valid_alert():
    """
    T-M1: map_to_alert({}) no debe explotar.

    Un payload vacío es posible si el webhook llega con campos opcionales
    ausentes o si la extracción previa ya eliminó información. El mapper
    debe producir un Alert válido usando valores por defecto, sin lanzar
    ninguna excepción.
    """
    alert = DependabotMapper.map_to_alert({})

    assert isinstance(alert, Alert)
    assert alert.source_type == AlertSource.dependabot
    assert alert.source_id == "unknown"
    assert alert.component == "unknown"
    assert alert.severity == AlertSeverity.unknown
    assert alert.status == AlertStatus.unknown
    assert alert.alert_id == "dependabot-unknown-unknown"
    assert isinstance(alert.first_seen, datetime)


def test_map_to_alert_complete_payload_maps_all_fields():
    """
    T-M1 (complemento): un payload completo debe mapear todos los campos correctamente.

    Verifica que los campos críticos (severity, status, component, alert_id)
    se extraen del payload real y no quedan en sus valores por defecto.
    """
    payload = {
        "number": 42,
        "state": "open",
        "html_url": "https://github.com/org/repo/security/dependabot/42",
        "created_at": "2024-03-01T10:00:00Z",
        "updated_at": "2024-03-02T12:00:00Z",
        "dependency": {
            "package": {"name": "requests", "ecosystem": "pip"},
            "manifest_path": "requirements.txt",
            "scope": "runtime",
        },
        "security_advisory": {
            "summary": "SSRF vulnerability in requests",
            "severity": "high",
            "cve_id": "CVE-2024-0001",
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cvss_severities": {"cvss_v3": {"score": 8.1}},
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}],
            "identifiers": [{"type": "CVE", "value": "CVE-2024-0001"}],
        },
        "security_vulnerability": {"severity": "high"},
    }

    alert = DependabotMapper.map_to_alert(payload)

    assert alert.source_id == "42"
    assert alert.severity == AlertSeverity.high
    assert alert.status == AlertStatus.open
    assert alert.component == "requests"
    assert alert.title == "SSRF vulnerability in requests"
    assert alert.external_references_score == 8.1
    assert alert.location == "https://github.com/org/repo/security/dependabot/42"


# ---------------------------------------------------------------------------
# T-M2 — _generate_alert_id con html_url presente
# ---------------------------------------------------------------------------

def test_generate_alert_id_with_html_url_follows_expected_format():
    """
    T-M2: _generate_alert_id con html_url debe seguir el formato dependabot-{owner}-{repo}-{number}.

    El alert_id es la clave de deduplicación en Supabase. Si cambia el formato
    entre versiones, el upsert inserta duplicados en lugar de actualizar el registro.
    """
    alert_data = {
        "number": 42,
        "html_url": "https://github.com/org/my-repo/security/dependabot/42",
    }

    alert_id = DependabotMapper._generate_alert_id(alert_data)

    assert alert_id.startswith("dependabot-")
    assert alert_id.endswith("-42")
    assert "org" in alert_id
    assert "my-repo" in alert_id


def test_generate_alert_id_is_lowercase():
    """
    T-M2 (complemento): el alert_id debe estar en minúsculas.

    Si el owner o repo tienen mayúsculas en GitHub, el ID generado podría
    variar entre llamadas si la normalización no es consistente.
    """
    alert_data = {
        "number": 7,
        "html_url": "https://github.com/SecuBotUdea/Parser-Dependabot/security/dependabot/7",
    }

    alert_id = DependabotMapper._generate_alert_id(alert_data)

    assert alert_id == alert_id.lower()


# ---------------------------------------------------------------------------
# T-M3 — _generate_alert_id sin html_url
# ---------------------------------------------------------------------------

def test_generate_alert_id_without_html_url_uses_fallback():
    """
    T-M3: cuando no hay html_url, el ID debe usar el formato dependabot-unknown-{number}.

    Algunas alertas de Dependabot pueden no incluir html_url (alertas muy antiguas
    o de orígenes no estándar). El mapper debe manejar este caso sin explotar.
    """
    alert_data = {"number": 99}

    alert_id = DependabotMapper._generate_alert_id(alert_data)

    assert alert_id == "dependabot-unknown-99"


def test_generate_alert_id_without_html_url_and_without_number():
    """
    T-M3 (complemento): sin html_url y sin number, el ID debe ser dependabot-unknown-unknown.
    """
    alert_id = DependabotMapper._generate_alert_id({})

    assert alert_id == "dependabot-unknown-unknown"


# ---------------------------------------------------------------------------
# T-M4 — _parse_datetime
# ---------------------------------------------------------------------------

def test_parse_datetime_with_z_suffix():
    """
    T-M4: fechas con sufijo Z deben parsearse correctamente.

    GitHub envía fechas en formato ISO 8601 con Z (ej. "2024-01-15T10:30:00Z").
    Python no acepta Z directamente en fromisoformat — el mapper debe convertirlo
    a +00:00 antes de parsear.
    """
    result = DependabotMapper._parse_datetime("2024-01-15T10:30:00Z")

    assert result.year == 2024
    assert result.month == 1
    assert result.day == 15
    assert result.hour == 10


def test_parse_datetime_with_standard_iso():
    """
    T-M4: fechas en formato ISO estándar con timezone explícito deben parsearse.
    """
    result = DependabotMapper._parse_datetime("2024-06-20T14:00:00+00:00")

    assert result.year == 2024
    assert result.month == 6
    assert result.day == 20


def test_parse_datetime_with_none_returns_datetime():
    """
    T-M4: cuando el campo de fecha es None (campo ausente), debe retornar
    un datetime válido (utcnow) sin lanzar excepción.

    Si se lanzara una excepción, todo el mapper fallaría por un campo de fecha
    opcional ausente.
    """
    result = DependabotMapper._parse_datetime(None)

    assert isinstance(result, datetime)


def test_parse_datetime_with_invalid_string_returns_datetime():
    """
    T-M4: una fecha con formato inválido debe retornar un datetime válido (utcnow)
    en lugar de propagar el ValueError.
    """
    result = DependabotMapper._parse_datetime("not-a-date")

    assert isinstance(result, datetime)


# ---------------------------------------------------------------------------
# T-M5 — _extract_severity
# ---------------------------------------------------------------------------

def test_extract_severity_valid_values():
    """
    T-M5: los valores estándar de severidad deben mapearse al enum correcto.
    """
    cases = [
        ("informational", AlertSeverity.informational),
        ("low", AlertSeverity.low),
        ("medium", AlertSeverity.medium),
        ("high", AlertSeverity.high),
        ("critical", AlertSeverity.critical),
    ]

    for raw, expected in cases:
        result = DependabotMapper._extract_severity(
            {"severity": raw}, {}
        )
        assert result == expected, f"Fallo para severity={raw!r}"


def test_extract_severity_uppercase_is_normalized():
    """
    T-M5: los valores en mayúsculas deben mapearse igual que en minúsculas.

    GitHub puede enviar "HIGH" o "High" dependiendo de la versión de la API.
    El mapper hace .lower() antes de buscar en el mapa, lo cual debe cubrir esto.
    """
    result = DependabotMapper._extract_severity({"severity": "CRITICAL"}, {})

    assert result == AlertSeverity.critical


def test_extract_severity_unknown_value_returns_unknown():
    """
    T-M5: un valor de severidad no reconocido debe retornar AlertSeverity.unknown.
    """
    result = DependabotMapper._extract_severity({"severity": "extreme"}, {})

    assert result == AlertSeverity.unknown


def test_extract_severity_missing_field_falls_back_to_vulnerability():
    """
    T-M5: si security_advisory no tiene severity, debe tomar el valor
    de security_vulnerability como fallback.
    """
    result = DependabotMapper._extract_severity(
        {},  # security_advisory sin severity
        {"severity": "medium"},  # security_vulnerability con severity
    )

    assert result == AlertSeverity.medium


def test_extract_severity_both_missing_returns_unknown():
    """
    T-M5: si ninguno de los dos campos tiene severity, debe retornar unknown.
    """
    result = DependabotMapper._extract_severity({}, {})

    assert result == AlertSeverity.unknown


# ---------------------------------------------------------------------------
# T-M6 — _extract_cvss_score
# ---------------------------------------------------------------------------

def test_extract_cvss_score_prefers_v4_over_v3():
    """
    T-M6: cuando existen cvss_v4 y cvss_v3, debe usarse cvss_v4 (mayor prioridad).
    """
    advisory = {
        "cvss_severities": {
            "cvss_v4": {"score": 9.5},
            "cvss_v3": {"score": 7.2},
        }
    }

    score = DependabotMapper._extract_cvss_score(advisory)

    assert score == 9.5


def test_extract_cvss_score_falls_back_to_v3_when_no_v4():
    """
    T-M6: si no hay cvss_v4, debe usar cvss_v3.
    """
    advisory = {
        "cvss_severities": {
            "cvss_v3": {"score": 7.2},
        }
    }

    score = DependabotMapper._extract_cvss_score(advisory)

    assert score == 7.2


def test_extract_cvss_score_falls_back_to_legacy_cvss():
    """
    T-M6: si no hay cvss_severities, debe intentar leer el campo cvss legacy.
    """
    advisory = {"cvss": {"score": 6.5}}

    score = DependabotMapper._extract_cvss_score(advisory)

    assert score == 6.5


def test_extract_cvss_score_returns_none_when_score_is_zero():
    """
    T-M6: un score de 0 no es un valor válido y debe retornar None.

    Un score 0.0 en CVSS indica que no hay puntuación real asignada.
    Guardarlo como 0.0 en Supabase podría confundirse con "sin severidad medible".
    """
    advisory = {"cvss_severities": {"cvss_v3": {"score": 0}}}

    score = DependabotMapper._extract_cvss_score(advisory)

    assert score is None


def test_extract_cvss_score_returns_none_when_all_absent():
    """
    T-M6: si no hay ninguna fuente de score, debe retornar None sin explotar.
    """
    score = DependabotMapper._extract_cvss_score({})

    assert score is None
