# parser-dependabot

Microservicio de ingesta y normalización de alertas de seguridad para el ecosistema **SecuBot-UdeA**. Recibe webhooks de GitHub (Dependabot), OWASP ZAP y Trivy, normaliza las alertas a un modelo canónico y las reenvía a `jug-eared` para su routing hacia los servicios de gamificación y notificación.

---

## Rol en la arquitectura

```
GitHub App (Dependabot)  ──┐
OWASP ZAP workflow       ──┤──► POST /webhook ──► parser-dependabot ──► jug-eared
Trivy SAST workflow      ──┘                           │
                                                       └──► Supabase (persistencia)

jug-eared ──► POST /verify/{alert_id}  (rescan)
```

El servicio actúa como la frontera de entrada del sistema: valida firmas HMAC, detecta la fuente del evento, normaliza el payload y persiste el alert en Supabase antes de reenviarlo.

---

## Endpoints

### `POST /webhook`

Recibe webhooks de GitHub App. Detecta automáticamente la fuente según el campo `source` del payload o el header `X-GitHub-Event`.

**Headers requeridos:**
| Header | Descripción |
|---|---|
| `X-Hub-Signature-256` | Firma HMAC-SHA256 del cuerpo. Requerida en producción. |
| `X-GitHub-Event` | Tipo de evento GitHub (`dependabot_alert`, `ping`, etc.) |
| `X-GitHub-Delivery` | ID único de entrega (para trazabilidad) |

**Detección de fuente:**
| `payload.source` | Fuente procesada |
|---|---|
| *(ausente / evento GitHub)* | `dependabot` |
| `owasp_zap` | OWASP ZAP |
| `trivy_sast` | Trivy SAST |

**Respuestas:**
- `200 {"status": "pong"}` — ping de GitHub App
- `200 {"status": "accepted"}` — alert recibido y encolado
- `400` — firma inválida o JSON malformado
- `500` — error de configuración del servidor

---

### `POST /verify/{alert_id}`

Dispara el rescan de una alerta existente. Llamado por `jug-eared` cuando un usuario solicita verificar si una alerta fue resuelta.

**Headers requeridos:**
| Header | Descripción |
|---|---|
| `X-Github-Token` | Token GitHub del equipo registrado en `jug-eared` |

**Comportamiento por fuente:**

- **Dependabot:** consulta directamente la GitHub API (`GET /repos/{owner}/{repo}/dependabot/alerts/{number}`) y resuelve el estado de inmediato.
- **ZAP / Trivy:** dispara el workflow correspondiente (`Owasp_Zap.yml` o `Trivy.yml`) vía `workflow_dispatch` y agrega el `alert_id` al watchlist interno. El estado final llega cuando el workflow re-entrega el webhook.

**Respuestas:**
- `200 {"status": "resolved", "github_state": "..."}` — Dependabot resuelto
- `200 {"status": "accepted"}` — ZAP/Trivy en espera de webhook
- `403` — token sin permisos
- `404` — alerta o recurso GitHub no encontrado
- `502` — GitHub API inalcanzable

---

### `GET /alerts/{alert_id}`

Recupera una alerta persistida por su ID.

**Respuestas:**
- `200` — objeto `Alert` completo
- `404` — alerta no encontrada

---

### `GET /`

Health check. Retorna `{"status": "ok"}`.

---

## Modelo canónico `Alert`

Todas las fuentes se normalizan a este esquema antes de ser reenviadas:

```python
class Alert(BaseModel):
    alert_id: str              # "{source}-{owner}-{repo}-{number}"
    source_type: AlertSource   # dependabot | zap | trivy
    source_id: str
    title: str
    severity: AlertSeverity    # informational | low | medium | high | critical | unknown
    status: AlertStatus        # open | fixed | dismissed | resolved | unknown
    component: str             # paquete/dependencia afectada
    location: str | None
    external_references_score: float | None   # score CVSS/referencias (0.0–1.0)
    first_seen: datetime
    last_seen: datetime | None
    normalized_payload: dict
    raw_payload: dict
    lifecycle_history: list
    reopen_count: int
    version: int
```

El campo `alert_id` sigue el formato `{source}-{owner}-{repo}-{number}`, que es el identificador compartido con el resto del ecosistema (jug-eared lo usa para resolver el equipo responsable).

---

## Variables de entorno

| Variable | Requerida | Descripción |
|---|---|---|
| `WEBHOOK_SECRET` | Sí (producción) | Secret HMAC para validar firma `X-Hub-Signature-256` |
| `SUPABASE_URL` | Sí | URL del proyecto Supabase |
| `SUPABASE_KEY` | Sí | API key de Supabase (service role) |
| `FORWARD_ALERTS_URL` | Sí | URL del endpoint `/alerts/` de `jug-eared` |
| `RESCAN_WAIT_SECONDS` | No (default: `60`) | Segundos de espera antes de marcar ZAP/Trivy como `fixed` si el workflow no re-entrega |
| `DEBUG` | No (default: `false`) | Si `true`, omite verificación de firma (solo desarrollo local) |

---

## Instalación y ejecución local

```bash
python -m venv .venv
source .venv/bin/activate

pip install --upgrade pip setuptools wheel
pip install .[dev]
```

Crear `.env` con las variables requeridas:

```env
WEBHOOK_SECRET=your_secret
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_KEY=your_service_role_key
FORWARD_ALERTS_URL=https://jug-eared.onrender.com/alerts/
DEBUG=false
```

Ejecutar:

```bash
uvicorn app.main:app --reload
```

---

## Tests

```bash
pytest -q
```

Con cobertura:

```bash
coverage run --source=app -m pytest -q
coverage report
```

La suite incluye tests para los tres mappers (Dependabot, ZAP, Trivy), el servicio de alertas, y los endpoints del webhook con fixtures JSON en `tests/fixtures/`.

---

## CI

GitHub Actions ejecuta la suite completa en Python 3.10 y 3.11 en cada push/PR a `main`. El pipeline corre pre-commit, pytest con cobertura, y publica los reportes como artefactos.

Secrets requeridos en el repositorio: `WEBHOOK_SECRET`, `SUPABASE_URL`, `SUPABASE_KEY`.

---

## Despliegue

El servicio incluye configuración para **Vercel** (`vercel.json`) apuntando a `app/main.py`.

> **Nota:** El watchlist de rescan (`_watchlist`) y el estado de Supabase lazy-init son en memoria por proceso. En despliegues con múltiples instancias o reinicios frecuentes, los rescans pendientes de ZAP/Trivy pueden perderse.

---

## Estructura del proyecto

```
app/
├── core/
│   └── config.py              # Cliente Supabase con lazy init
├── models/
│   └── alert_model.py         # Modelo canónico Alert + enums
├── repositories/
│   ├── base_repo.py           # Interfaz BaseRepository[T]
│   └── alert_repo.py          # AlertRepository (Supabase)
├── routes/
│   ├── get_alert_by_id.py
│   ├── items/
│   │   └── get_alert_service.py   # Dependency injection
│   └── webhook/
│       ├── router.py          # Endpoints /webhook y /verify
│       ├── processor.py       # Lógica de normalización y watchlist
│       └── security.py        # Verificación HMAC-SHA256
└── services/
    ├── alert_service.py       # Orquestador de mappers y repo
    └── mappers/
        ├── dependabot_mapper.py
        ├── zap_mapper.py
        └── trivy_mapper.py
```
