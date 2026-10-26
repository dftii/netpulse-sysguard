# CLAUDE.md — NetPulse SysGuard

Contexto para que Claude retome el proyecto en cualquier máquina.

## Usuario y forma de trabajar

- Habla con el usuario **en español**. Código, identificadores, comentarios y commits en **inglés**.
- Proyecto de **portafolio** para GitHub (`https://github.com/dftii/netpulse-sysguard`, rama `main`). Debe demostrar experiencia en administración de sistemas, diagnóstico de hardware, redes locales, Python y análisis de datos.
- **Regla estricta:** nada de placeholders, TODOs, código resumido ni comentarios del tipo "resto de la lógica aquí". Todo el código debe ser 100 % funcional, modular y listo para producción.
- **Orquestación pedida por el usuario:** Opus planifica y audita. Las tareas complejas van a subagentes **Sonnet** con esfuerzo alto, y las simples a subagentes **Haiku** con esfuerzo alto. Escribe primero los contratos compartidos (schemas, interfaces) y después delega los módulos en paralelo, cada uno con ficheros propios y sin solapes.
- El usuario usó `/caveman`: respuestas concisas, sin relleno.

## Fases

1. **Fase 1 — Backend: COMPLETADA.** 158 tests en verde. Subida en el commit `ec9e029`.
2. **Fase 2 — Frontend: PENDIENTE (siguiente paso).** Dashboard en React 18 + Vite + TypeScript + TailwindCSS + Recharts que consume `ws://localhost:8000/ws/telemetry` y la API REST. El plan de carpetas está en `frontend/README.md`, y `frontend/src/{components,hooks,pages,services,types}` solo contienen `.gitkeep`.
3. **Fase 3 — Despliegue y hardening: PENDIENTE.** El usuario aún no la ha detallado. Lo previsible es Docker/compose, CI con GitHub Actions y pulido del README con capturas.

## Stack del backend

Python 3.11+ · FastAPI · WebSockets · Pydantic v2 + pydantic-settings · SQLAlchemy 2.0 async + aiosqlite (SQLite en WAL) · psutil · asyncio/socket · pytest + pytest-asyncio.

Las versiones están fijadas en `backend/requirements.txt`. Se fijaron versiones recientes porque pydantic 2.11 no tiene wheels para Python 3.14. SQLAlchemy se mantiene en la rama 2.0 (`2.0.55`), tal como pidió el usuario.

## Estructura y responsabilidades

```
backend/app/
  config.py      Settings (todas las variables de entorno llevan el prefijo NETPULSE_; ver backend/.env.example)
  enums.py       NodeRole, NodeStatus, RiskLevel, PortState, AnomalyType, AlertSeverity, ExportFormat
  database.py    async engine, SessionLocal, get_session, init_db (create_all), PRAGMAs de SQLite
  models.py      Node, MetricSample, PortAudit, PortFinding, AnomalyAlert
  schemas.py     contratos Pydantic: NodeTelemetry (snapshot en vivo), TelemetryBroadcast (frame WS),
                 PortScanRequest/PortScanOutcome/PortAuditRead, AnomalyAlertCreate/Read, AlertPage...
  crud.py        todas las queries (upsert_nodes, record_tick, query_alerts, save_port_audit, purge...)
  ws_manager.py  ConnectionManager: broadcast concurrente y expulsión de clientes lentos
  main.py        lifespan + telemetry_loop (1 s) + retention_loop + todos los endpoints
  services/
    telemetry_collector.py  TelemetryCollector = HostTelemetrySource (psutil real) + EnterpriseClusterSimulator (8 nodos)
    network_scanner.py      NetworkScanner async TCP connect, banners, latencia, COMMON_PORTS (44), ScanTargetError
    anomaly_detector.py     RollingStatistics, linear_regression, AnomalyDetector (Z-Score, leak por regresión, cooldown)
    report_exporter.py      exportación de alertas, métricas y auditorías a JSON/CSV + build_filename
backend/tests/   conftest.py (BD temporal + variables de entorno) y una suite por módulo + test_api.py (E2E)
```

Pipeline por tick: `collector.collect()` → `detector.analyze_and_persist()` → escalado de estado → `crud.record_tick()` (métricas cada `metrics_persist_every_n_ticks`) → `ws_manager.broadcast(TelemetryBroadcast)`.

Detalles a tener en cuenta:
- Usa un solo worker de uvicorn: el estado (baselines, simulador, clientes WS) vive en memoria.
- SQLite pierde la zona horaria. Todo se guarda en UTC, y `UTCDateTime` en schemas vuelve a añadir UTC al leer.
- `build_filename` solo acepta prefijos `[A-Za-z0-9_-]`. `main.attachment()` sanea el prefijo antes de llamarla.
- Por defecto el escáner solo acepta IPs privadas, de loopback o link-local (`NETPULSE_SCAN_ALLOW_PUBLIC_TARGETS`). Un `429` indica que hay más de 2 escaneos simultáneos.
- El simulador solo llega a valores críticos durante incidentes, sean aleatorios o inyectados con `POST /api/simulation/incidents`.

## API (resumen para el frontend)

- `WS /ws/telemetry`: un frame `TelemetryBroadcast` por segundo con los campos `{type, timestamp, tick, summary, nodes[], new_alerts[]}`. Si el cliente envía `ping`, recibe `{"type":"pong"}`.
- `GET /api/health`, `GET /api/telemetry/latest`
- `GET /api/nodes`, `/api/nodes/{id}`, `/api/nodes/{id}/metrics?minutes=`, `/api/nodes/{id}/baseline`
- `POST /api/scans`, `GET /api/scans`, `GET /api/scans/{id}`
- `GET /api/alerts`, con los filtros `node_id`, `severity`, `anomaly_type`, `acknowledged`, `since`, `until`, `limit` y `offset`
- `PATCH /api/alerts/{id}/acknowledge`
- `POST /api/simulation/incidents`
- `GET /api/reports/incidents|metrics/{node_id}|scans/{id}?format=json|csv`

CORS admite por defecto `localhost:5173` y `localhost:3000`.

## Puesta en marcha (máquina nueva)

```bash
cd backend
python -m venv .venv            # Python 3.11+ (en el PC original: 3.14)
.venv/Scripts/activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
pytest                          # esperado: 158 passed
python run.py                   # http://127.0.0.1:8000/docs
```

Si `pip` falla compilando `pydantic-core`, la versión de Python no tiene wheels para los pins. Usa Python 3.12, 3.13 o 3.14.
