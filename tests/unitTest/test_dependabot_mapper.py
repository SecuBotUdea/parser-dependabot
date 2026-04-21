from datetime import datetime

import pytest

from app.models.alert_model import Alert, AlertSeverity, AlertSource, AlertStatus
from app.services.mappers.dependabot_mapper import DependabotMapper


# ---------------------------------------------------------------------------
# T-M1 — map_to_alert
# ---------------------------------------------------------------------------

def test_map_to_alert_empty_dict_uses_all_defaults():
    # Arrange
    payload = {}

    # Act
    alert = DependabotMapper.map_to_alert(payload)

    # Assert
    assert isinstance(alert, Alert)
    assert alert.source_type == AlertSource.dependabot
    assert alert.source_id == "unknown"
    assert alert.component == "unknown"
    assert alert.severity == AlertSeverity.unknown
    assert alert.status == AlertStatus.unknown
    assert alert.alert_id == "dependabot-unknown-unknown"
    assert isinstance(alert.first_seen, datetime)


def test_map_to_alert_complete_payload_maps_all_fields():
    # Arrange
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

    # Act
    alert = DependabotMapper.map_to_alert(payload)

    # Assert
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
    # Arrange
    alert_data = {
        "number": 42,
        "html_url": "https://github.com/SecuBotUdea/My-Repo/security/dependabot/42",
    }

    # Act
    alert_id = DependabotMapper._generate_alert_id(alert_data)

    # Assert
    assert alert_id.startswith("dependabot-")
    assert alert_id.endswith("-42")
    assert "secubotudea" in alert_id
    assert "my-repo" in alert_id
    assert alert_id == alert_id.lower()


# ---------------------------------------------------------------------------
# T-M3 — _generate_alert_id sin html_url
# ---------------------------------------------------------------------------

def test_generate_alert_id_without_html_url_uses_fallback():
    # Arrange
    alert_data = {"number": 99}

    # Act
    alert_id = DependabotMapper._generate_alert_id(alert_data)

    # Assert
    assert alert_id == "dependabot-unknown-99"


def test_generate_alert_id_without_html_url_and_without_number():
    # Arrange
    alert_data = {}

    # Act
    alert_id = DependabotMapper._generate_alert_id(alert_data)

    # Assert
    assert alert_id == "dependabot-unknown-unknown"


# ---------------------------------------------------------------------------
# T-M4 — _parse_datetime
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("date_str,expected_year,expected_month,expected_day", [
    ("2024-01-15T10:30:00Z", 2024, 1, 15),
    ("2024-06-20T14:00:00+00:00", 2024, 6, 20),
])
def test_parse_datetime_with_valid_string_returns_correct_date(
    date_str, expected_year, expected_month, expected_day
):
    # Arrange — date_str provisto por parametrize

    # Act
    result = DependabotMapper._parse_datetime(date_str)

    # Assert
    assert result.year == expected_year
    assert result.month == expected_month
    assert result.day == expected_day


@pytest.mark.parametrize("invalid_input", [None, "not-a-date"])
def test_parse_datetime_with_invalid_input_returns_valid_datetime(invalid_input):
    # Arrange — invalid_input provisto por parametrize

    # Act
    result = DependabotMapper._parse_datetime(invalid_input)

    # Assert
    assert isinstance(result, datetime)


# ---------------------------------------------------------------------------
# T-M5 — _extract_severity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("informational", AlertSeverity.informational),
    ("low", AlertSeverity.low),
    ("medium", AlertSeverity.medium),
    ("high", AlertSeverity.high),
    ("critical", AlertSeverity.critical),
    ("CRITICAL", AlertSeverity.critical),
])
def test_extract_severity_maps_known_values(raw, expected):
    # Arrange — raw/expected provistos por parametrize

    # Act
    result = DependabotMapper._extract_severity({"severity": raw}, {})

    # Assert
    assert result == expected


def test_extract_severity_unknown_value_returns_unknown():
    # Arrange
    advisory = {"severity": "extreme"}

    # Act
    result = DependabotMapper._extract_severity(advisory, {})

    # Assert
    assert result == AlertSeverity.unknown


def test_extract_severity_falls_back_to_vulnerability_when_advisory_missing():
    # Arrange
    advisory = {}
    vulnerability = {"severity": "medium"}

    # Act
    result = DependabotMapper._extract_severity(advisory, vulnerability)

    # Assert
    assert result == AlertSeverity.medium


def test_extract_severity_returns_unknown_when_both_sources_missing():
    # Arrange
    advisory = {}
    vulnerability = {}

    # Act
    result = DependabotMapper._extract_severity(advisory, vulnerability)

    # Assert
    assert result == AlertSeverity.unknown


# ---------------------------------------------------------------------------
# T-M6 — _extract_cvss_score
# ---------------------------------------------------------------------------

def test_extract_cvss_score_prefers_v4_over_v3():
    # Arrange
    advisory = {
        "cvss_severities": {
            "cvss_v4": {"score": 9.5},
            "cvss_v3": {"score": 7.2},
        }
    }

    # Act
    score = DependabotMapper._extract_cvss_score(advisory)

    # Assert
    assert score == 9.5


def test_extract_cvss_score_falls_back_to_v3_when_no_v4():
    # Arrange
    advisory = {"cvss_severities": {"cvss_v3": {"score": 7.2}}}

    # Act
    score = DependabotMapper._extract_cvss_score(advisory)

    # Assert
    assert score == 7.2


def test_extract_cvss_score_falls_back_to_legacy_cvss():
    # Arrange
    advisory = {"cvss": {"score": 6.5}}

    # Act
    score = DependabotMapper._extract_cvss_score(advisory)

    # Assert
    assert score == 6.5


def test_extract_cvss_score_returns_none_when_score_is_zero():
    # Arrange
    advisory = {"cvss_severities": {"cvss_v3": {"score": 0}}}

    # Act
    score = DependabotMapper._extract_cvss_score(advisory)

    # Assert
    assert score is None


def test_extract_cvss_score_returns_none_when_all_absent():
    # Arrange
    advisory = {}

    # Act
    score = DependabotMapper._extract_cvss_score(advisory)

    # Assert
    assert score is None
