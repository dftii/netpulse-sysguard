# NetPulse SysGuard

IT infrastructure monitoring, local network auditing and real-time anomaly detection platform.

NetPulse SysGuard collects **real hardware and network telemetry** from the host machine with `psutil`, augments it with a **simulated 8-server enterprise cluster**, streams everything over **WebSockets** every second, detects anomalies with **rolling Z-Score statistics and linear regression**, audits exposed TCP ports with a **risk classification engine**, and keeps a full incident history in **SQLite** for JSON/CSV technical reports.

> Phase 1 (this release): architecture + complete backend. Phase 2: React dashboard. Phase 3: deployment and hardening.

## Architecture

```
                 ┌──────────────────────────── FastAPI process ────────────────────────────┐
                 │                                                                         │
 psutil ───────► │  TelemetryCollector ──┐                                                 │
 (real host)     │   ├ HostTelemetrySource│  every 1 s                                     │
                 │   └ EnterpriseCluster  ├──► AnomalyDetector ──► SQLite (alerts)          │
                 │     Simulator (8 nodes)│      Z-Score / regression                      │
                 │                        ├──► crud.record_tick ──► SQLite (metrics, status)│
                 │                        └──► ConnectionManager ──► /ws/telemetry ────────►│──► Dashboard
                 │                                                                         │
 REST client ──► │  /api/scans ──► NetworkScanner (asyncio + socket) ──► SQLite (audits)   │
                 │  /api/alerts, /api/reports/* ──► report_exporter (JSON / CSV)           │
                 └─────────────────────────────────────────────────────────────────────────┘
```

## Project layout

```
netpulse-sysguard/
├── backend/
│   ├── app/
│   │   ├── config.py                 # Pydantic Settings (NETPULSE_* env vars)
│   │   ├── enums.py                  # Shared domain enums
│   │   ├── database.py               # Async SQLAlchemy 2.0 engine, WAL SQLite
│   │   ├── models.py                 # ORM: Node, MetricSample, PortAudit, PortFinding, AnomalyAlert
│   │   ├── schemas.py                # Pydantic v2 API / stream contracts
│   │   ├── crud.py                   # Data-access layer
│   │   ├── ws_manager.py             # WebSocket fan-out with slow-client eviction
│   │   ├── main.py                   # FastAPI app, lifespan, pipeline, REST + WS endpoints
│   │   └── services/
│   │       ├── telemetry_collector.py  # psutil host source + enterprise cluster simulator
│   │       ├── network_scanner.py      # Async TCP port audit, banners, latency, risk scoring
│   │       ├── anomaly_detector.py     # Rolling Z-Score, leak regression, cooldowns
│   │       └── report_exporter.py      # JSON / CSV technical reports
│   ├── tests/                        # pytest suite (unit + end-to-end)
│   ├── data/                         # SQLite database (git-ignored)
│   ├── run.py                        # Server entry point
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   ├── pytest.ini
│   └── .env.example
├── frontend/                         # Phase 2 (React + Vite + TypeScript)
├── LICENSE
└── README.md
```

## Simulated enterprise cluster

| Hostname | Role | Profile |
|---|---|---|
| `db-primary-01` | Database | PostgreSQL 16, memory-heavy |
| `lb-edge-01` | Load balancer | HAProxy, network-heavy |
| `ai-gpu-node-01` | AI compute | Bursty CPU/RAM inference node |
| `fw-core-01` | Firewall | pfSense, high throughput |
| `web-app-01` | Web server | nginx application tier |
| `cache-redis-01` | Cache | Redis in-memory store |
| `nas-storage-01` | Storage | TrueNAS, high disk usage |
| `dc-ad-01` | Domain controller | Windows Server 2022 AD |

Each node combines a role baseline, a diurnal (time-of-day) load curve and mean-reverting noise. Random incidents (CPU spike, memory leak, bandwidth saturation, critical latency, disk pressure) occur on their own, and you can inject them on demand through the API.

## Anomaly detection

| Detector | Method |
|---|---|
| CPU spike | Z-Score against a rolling window (value scored before entering the baseline) plus a sustained absolute threshold |
| Memory leak | Least-squares slope and R² over a sliding window, with projected time to exhaustion |
| Bandwidth saturation | Link utilisation % against NIC capacity, plus Z-Score bursts |
| Critical latency | Absolute threshold plus Z-Score relative to the baseline |
| Disk pressure | Absolute threshold plus Z-Score jumps |

During a sustained incident the baseline is frozen, so the anomaly does not become the new normal. Cooldowns are applied per node and per anomaly type to prevent alert floods. A WARNING alert can still escalate to CRITICAL during the cooldown.

## Port auditing

The scanner runs an asynchronous TCP connect scan with bounded concurrency. It classifies each port as open, closed (RST) or filtered (timeout). On open ports it grabs service banners and escalates the risk of outdated versions such as old OpenSSH or vsFTPd 2.3.4. Host latency is measured over TCP, with an ICMP fallback. The built-in catalogue covers 44 common services, each with a risk level, a reason and a remediation recommendation. Only private, loopback and link-local targets are allowed by default (`NETPULSE_SCAN_ALLOW_PUBLIC_TARGETS=false`).

## Quick start

Requires Python 3.11 or newer.

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate        # Windows (Linux/macOS: source .venv/bin/activate)
pip install -r requirements-dev.txt
cp .env.example .env          # optional
python run.py                 # http://127.0.0.1:8000/docs
```

Run the tests:

```bash
cd backend
pytest
```

## API

| Method | Path | Description |
|---|---|---|
| WS | `/ws/telemetry` | Live `TelemetryBroadcast` frame every second (send `ping` to receive `pong`) |
| GET | `/api/health` | Service, database and pipeline health |
| GET | `/api/telemetry/latest` | Most recent snapshot of every node |
| GET | `/api/nodes` | Monitored nodes |
| GET | `/api/nodes/{id}` | Node detail |
| GET | `/api/nodes/{id}/metrics?minutes=60` | Historical metrics |
| GET | `/api/nodes/{id}/baseline` | Current detector baselines (mean / std per metric) |
| POST | `/api/scans` | Run a port audit `{ "target": "192.168.1.1", "ports": [22, 80], "port_range": [1, 1024] }` |
| GET | `/api/scans` | Audit history |
| GET | `/api/scans/{id}` | Audit detail with findings |
| GET | `/api/alerts` | Incident history (filters: `node_id`, `severity`, `anomaly_type`, `acknowledged`, `since`, `until`) |
| PATCH | `/api/alerts/{id}/acknowledge` | Acknowledge an incident |
| POST | `/api/simulation/incidents` | Inject an incident on a simulated node |
| GET | `/api/reports/incidents?format=json\|csv` | Incident report |
| GET | `/api/reports/metrics/{node_id}?hours=24&format=csv` | Metrics report |
| GET | `/api/reports/scans/{id}?format=json` | Port audit report |

Example: inject a memory leak and watch the detector catch it.

```bash
curl -X POST http://127.0.0.1:8000/api/simulation/incidents -H "Content-Type: application/json" -d "{\"hostname\": \"db-primary-01\", \"anomaly_type\": \"memory_leak\", \"duration_seconds\": 120}"
```

## Configuration

All settings use the `NETPULSE_` prefix. See [backend/.env.example](backend/.env.example) for the full list, which covers telemetry interval, retention, detector thresholds, scanner limits and CORS origins.

## Tech stack

Python 3.11+ · FastAPI · WebSockets · Pydantic v2 · SQLAlchemy 2.0 (async) · SQLite (WAL) · psutil · asyncio/socket · pytest

## License

MIT. See [LICENSE](LICENSE).
