# tests/test_mapper.py
import json

from app.mapper import map_dependabot_payload


def test_map_dependabot_payload_basic():
    # Carga el payload de alerta desde el archivo principal
    with open("alert.txt", "r", encoding="utf-8") as f:
        raw = json.load(f)

    mapped = map_dependabot_payload(raw)

    # ---- Validaciones del mapeo ----
    assert mapped["id"] == "PangoAguirre/aprendiendo-react#33"
    assert mapped["source"] == "dependabot"

    # Fecha normalizada a ISO con zona horaria
    assert mapped["created_at"] == "2025-10-18T02:21:07+00:00"

    # Información del paquete
    pkg = mapped["package"]
    assert pkg["name"] == "vite"
    assert pkg["ecosystem"] == "npm"
    # Debe tomar la primera versión parcheada del advisory
    assert pkg["fixed_version"] == "7.1.5"

    # Severidad y CVSS
    assert mapped["severity"] == "low"
    assert mapped["cvss"] == 2.3

    # Lista de CVEs
    assert isinstance(mapped["cve"], list)
    assert "CVE-2025-58751" in mapped["cve"]

    # Ubicación del archivo vulnerable
    loc = mapped["location"]
    assert loc["file"] == "projects/05-react-buscador-pelicula/pnpm-lock.yaml"
    assert loc["path"].startswith("PangoAguirre/aprendiendo-react/")

    # Verifica que el campo raw exista
    assert isinstance(mapped["raw"], dict)
