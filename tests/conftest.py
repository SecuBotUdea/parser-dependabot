import json
from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir():
    """Retorna el path al directorio de fixtures."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def load_fixture(fixtures_dir):
    """Factory fixture para cargar archivos JSON."""

    def _load(filename: str):
        filepath = fixtures_dir / filename
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    return _load


@pytest.fixture
def complete_webhook(load_fixture):
    """Carga el webhook completo de Dependabot."""
    return load_fixture("dependabot_webhook_complete.json")


@pytest.fixture
def webhook_no_cve(load_fixture):
    """Carga webhook sin CVE (solo GHSA)."""
    return load_fixture("dependabot_webhook_no_cve.json")


@pytest.fixture
def webhook_minimal(load_fixture):
    """Carga webhook con datos mínimos."""
    return load_fixture("dependabot_webhook_minimal.json")
