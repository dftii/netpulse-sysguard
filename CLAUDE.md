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
2. **Fase 2 — Backend empresarial: COMPLETADA.** 225 tests en verde (217 al cierre de la fase; 8 más en la auditoría). Incluye las anomalías SERVICE_DOWN y THERMAL_SPIKE (en el detector y en el simulador), `seed.py` idempotente con `--reset`, Docker y compose, y `.dockerignore`.
3. **Fase 3 — Frontend NOC + README: COMPLETADA.** React 19, TypeScript strict, Vite 8, Tailwind 4 y Lucide. Las gráficas son SVG nativo, sin Recharts: así lo pidió el prompt de la Fase 3, que sustituyó el plan anterior de React 18 + Recharts. Incluye un modo backend real, un motor de simulación en el navegador para GitHub Pages, CI (`ci.yml`) y deploy a Pages con GitHub Actions (`deploy.yml`, en cada push a main). La cabecera tiene un botón "Export report" que descarga un informe JSON (`lib/auditReport.ts`) y funciona en los dos modos. Lo siguiente previsible es añadir capturas al README.

## Frontend (frontend/)

```
src/types/api.ts          espejo TS de enums.py/schemas.py (si cambia un schema del backend, actualízalo aquí)
src/types/dashboard.ts    TelemetryState, TelemetryController (contrato hook → componentes), LogEntry
src/services/telemetrySource.ts   interfaz TelemetrySource común + SourceError
src/services/{apiClient,backendSource,modeResolver}.ts   REST, WS con reconexión/ping, detección de modo
src/services/simulation/  port TS del simulador, detector, catálogo de puertos (44) y escáner del backend
src/hooks/useTelemetry.ts (+ telemetryReducer.ts, scanLogs.ts)   un dispatch por frame, historial 120 s, logs
src/components/{header,servers,charts,ui,scanner,incidents,console}/   App.tsx solo compone
```

- Detección de modo: primero manda `VITE_DEFAULT_MODE`; después, un host `*.github.io` va a simulación; después, una elección "simulation" guardada en localStorage (`netpulse.mode`); por último, un probe a `/api/health` con timeout de 1,5 s. El build de Pages usa `VITE_DEFAULT_MODE=simulation`. `vite.config.ts` lleva `base: "./"`.
- En la simulación, `zscoreThreshold` es 6 y la amplitud de los bursts está al 35 %. Con los valores del backend (z=3) salían falsas alarmas en reposo, aproximadamente una cada 23 s.
- Pendientes conocidos, en el backend: con z=3 también genera alertas en reposo. Además, el uso de ancho de banda divide subida+bajada entre la capacidad de un solo sentido, y por eso salen valores de hasta ~180 %.
- Dev: `npm --prefix frontend run dev` (5173). Las versiones npm están fijadas (todas tienen más de 2 semanas de antigüedad). `.claude/launch.json` define las previsualizaciones de frontend y backend.

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
backend/seed.py   seed idempotente: los 8 nodos del simulador (mismos hostnames), 200 métricas por nodo en 24 h,
                  alertas de todos los AnomalyType y PortAudit con findings críticos (usa el catálogo del escáner)
backend/Dockerfile  python:3.12-slim, usuario no-root (uid 10001), VOLUME /app/data, HEALTHCHECK /api/health, 1 worker
docker-compose.yml  servicio backend (127.0.0.1:8000) + servicio `seed` bajo el profile "seed"
backend/tests/   conftest.py (BD temporal + variables de entorno) y una suite por módulo + test_seed.py + test_api.py (E2E)
```

Pipeline por tick: `collector.collect()` → `detector.analyze_and_persist()` → escalado de estado → `crud.record_tick()` (métricas cada `metrics_persist_every_n_ticks`) → `ws_manager.broadcast(TelemetryBroadcast)`.

Detalles a tener en cuenta:
- Usa un solo worker de uvicorn: el estado (baselines, simulador, clientes WS) vive en memoria.
- SQLite pierde la zona horaria. Todo se guarda en UTC, y `UTCDateTime` en schemas vuelve a añadir UTC al leer.
- `build_filename` solo acepta prefijos `[A-Za-z0-9_-]`. `main.attachment()` sanea el prefijo antes de llamarla.
- Por defecto el escáner solo acepta IPs privadas, de loopback o link-local (`NETPULSE_SCAN_ALLOW_PUBLIC_TARGETS`). Un `429` indica que hay más de 2 escaneos simultáneos.
- El simulador solo llega a valores críticos durante incidentes, sean aleatorios o inyectados con `POST /api/simulation/incidents`. En operación normal la temperatura no pasa de 78 °C, y el umbral de aviso está en 80 °C.
- SERVICE_DOWN: el nodo se emite con `status=offline`, métricas a 0, y `latency_ms` y `temperature_c` a `None`. El detector cuenta las muestras OFFLINE consecutivas sin tocar los baselines y alerta al llegar a `NETPULSE_ANOMALY_SERVICE_DOWN_SAMPLES`. `run_tick` nunca escala un nodo OFFLINE a CRITICAL.
- Seed: se salta una tabla de un nodo si ese nodo ya tiene filas con más de 1 h de antigüedad. `--reset` borra solo los datos de los 8 nodos sembrados y nunca toca el host real.
- En Docker, psutil mide el contenedor o la VM, no el host. Para telemetría real hay que usar `python run.py` en nativo.

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
pytest                          # esperado: 225 passed
python seed.py                  # opcional: datos demo de 24 h (--reset para regenerarlos)
python run.py                   # http://127.0.0.1:8000/docs
```

Frontend: `cd frontend && npm install && npm run dev` (http://localhost:5173), y para producción `npm run build`.

Con Docker: `docker compose up -d --build` y, opcionalmente, `docker compose --profile seed run --rm seed`.

Si `pip` falla compilando `pydantic-core`, la versión de Python no tiene wheels para los pins. Usa Python 3.12, 3.13 o 3.14.
