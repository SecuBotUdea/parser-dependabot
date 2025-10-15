# Parser Dependabot

## Instalar localmente
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install .[dev]

## Ejecutar tests
pytest -q

## Ejecutar FastApi (localmente)
uvicorn app.main:app --reload

## Ejecutar pre-commit localmente
pre-commit install
pre-commit run --all-files