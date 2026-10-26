<div align="center">

# NetPulse SysGuard

**IT infrastructure monitoring, local network auditing and real-time anomaly detection — with a live NOC dashboard.**

[![Live Demo](https://img.shields.io/badge/%E2%96%B6%20LIVE%20DEMO-GitHub%20Pages-22d3ee?style=for-the-badge&logo=github&logoColor=white)](https://dftii.github.io/netpulse-sysguard/)

[![CI](https://github.com/dftii/netpulse-sysguard/actions/workflows/ci.yml/badge.svg)](https://github.com/dftii/netpulse-sysguard/actions/workflows/ci.yml)
[![Deploy](https://github.com/dftii/netpulse-sysguard/actions/workflows/deploy.yml/badge.svg)](https://github.com/dftii/netpulse-sysguard/actions/workflows/deploy.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
<br />
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](backend/requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-WebSockets-009688?logo=fastapi&logoColor=white)](backend/app/main.py)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0%20async-D71F00?logo=sqlalchemy&logoColor=white)](backend/app/database.py)
[![pytest](https://img.shields.io/badge/tests-225%20passed-0A9EDC?logo=pytest&logoColor=white)](backend/tests)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](frontend/package.json)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](frontend/tsconfig.app.json)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white)](frontend/vite.config.ts)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind%20CSS-4-06B6D4?logo=tailwindcss&logoColor=white)](frontend/src/index.css)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)

</div>

NetPulse SysGuard collects **real hardware and network telemetry** from the host machine with `psutil`, augments it with a **simulated 8-server enterprise cluster**, streams everything over **WebSockets** every second, detects anomalies with **rolling Z-Score statistics and linear regression**, audits exposed TCP ports with a **risk classification engine**, and keeps a full incident history in **SQLite** for JSON/CSV technical reports. A React **Network Operations Center (NOC) dashboard** visualises it all in real time.

> **The live demo needs no server.** On GitHub Pages the dashboard detects that no backend is reachable and switches to an **in-browser simulation engine**: a TypeScript port of the backend's cluster simulator, Z-Score detector and port-risk catalogue. Metrics stream every second, you can launch simulated port audits, inject incidents and watch alerts fire. Run the backend locally and the same UI switches to **real telemetry**.

## Features

| Area | What it does |
|---|---|
| **Telemetry** | Real host CPU, RAM, disk, network throughput, temperatures and TCP latency via `psutil`, plus 8 simulated enterprise servers with diurnal load curves, mean-reverting noise and bursts. |
| **Anomaly detection** | Rolling Z-Score per node and metric, least-squares memory-leak detection, absolute thresholds, baseline freezing and per-type cooldowns. Seven anomaly types. |
| **Port auditing** | Async TCP connect scan with bounded concurrency, banner grabbing, version-based risk escalation (e.g. vsFTPd 2.3.4) and remediation advice for 44 common services. |
| **Streaming** | One `TelemetryBroadcast` frame per second over `/ws/telemetry`, with concurrent fan-out and slow-client eviction. |
| **History & reports** | SQLite (WAL) storage for metrics, alerts and audits, with JSON/CSV exports and retention. |
| **NOC dashboard** | KPIs, live server grid with threshold-coloured bars, native SVG real-time charts, terminal-style port audit console, incident panel and a live `journalctl`-style log console. |
| **Ops** | Idempotent 24 h demo seeder, Docker image (non-root, healthcheck), CI and GitHub Pages deployment. |

## Architecture

```mermaid
flowchart LR
    subgraph Sources["Data sources"]
        PS["psutil<br/>(real host: CPU, RAM, disk,<br/>NIC counters, sensors)"]
        SIM["EnterpriseClusterSimulator<br/>(8 servers, incidents)"]
        LAT["TCP latency probe"]
    end

    subgraph Backend["FastAPI process · single worker"]
        COL["TelemetryCollector<br/>tick every 1 s"]
        DET["AnomalyDetector<br/>rolling Z-Score · regression<br/>thresholds · cooldowns"]
        CRUD["crud.record_tick<br/>status escalation"]
        WSM["ConnectionManager<br/>WebSocket fan-out"]
        SCN["NetworkScanner<br/>asyncio + socket<br/>banners · risk scoring"]
        REP["report_exporter<br/>JSON / CSV"]
        DB[("SQLite WAL<br/>nodes · metrics<br/>alerts · audits")]
    end

    subgraph Frontend["React NOC dashboard"]
        HOOK["useTelemetry<br/>TelemetrySource interface"]
        BSRC["BackendSource<br/>REST + WS client"]
        BROWSER["SimulationSource<br/>in-browser engine<br/>(GitHub Pages)"]
        UI["KPIs · server grid · SVG charts<br/>port audit console · incidents · logs"]
    end

    PS --> COL
    SIM --> COL
    LAT --> COL
    COL --> DET
    DET -->|alerts| DB
    DET --> CRUD
    CRUD -->|metrics, status| DB
    CRUD --> WSM
    WSM -->|"/ws/telemetry · 1 frame/s"| BSRC
    SCN -->|audits| DB
    DB --> REP
    BSRC -->|"/api/scans · /api/alerts · /api/reports"| SCN
    BSRC --> HOOK
    BROWSER --> HOOK
    HOOK --> UI
```

Pipeline per tick: `collector.collect()` → `detector.analyze_and_persist()` → status escalation → `crud.record_tick()` → `ws_manager.broadcast()`.

## Anomaly detection algorithm

For every node and metric the detector keeps a **rolling window** (default `W = 60` samples) and maintains its mean and variance in **O(1)** per sample with Welford's algorithm extended with sample removal (periodically recomputed exactly to cancel floating-point drift).

Each new value `x` is scored **before** it joins the baseline, so an anomaly never inflates the statistics it is judged against:

$$z = \frac{x - \mu_{W}}{\sigma_{W}}$$

A reading is anomalous when `z ≥ 3` (configurable) once at least 20 samples exist, combined with absolute floors so that tiny fluctuations on an idle server never alert. While a metric stays anomalous its samples are **withheld from the baseline** (baseline freezing); if the condition outlasts the window, it is accepted as the new normal.

| Detector | Method |
|---|---|
| CPU spike | Z-Score with an absolute floor, plus sustained load above 90 % for 3 samples |
| Memory leak | Least-squares slope and R² over a sliding window (slope ≥ 0.08 %/s, R² ≥ 0.85), with projected time to exhaustion |
| Bandwidth saturation | Link utilisation against NIC capacity, plus Z-Score bursts on busy links |
| Critical latency | Absolute limit (250 ms) plus a large jump relative to the baseline |
| Disk pressure | Absolute fill level (92 %) plus sudden jumps on an already full disk |
| Service down | Node OFFLINE for N consecutive samples; offline samples never touch the baselines |
| Thermal spike | Warning / critical limits (80 / 90 °C) plus Z-Score jumps above 70 °C |

Cooldowns are applied per node and per anomaly type to prevent alert floods, but a WARNING can still escalate to CRITICAL during the cooldown. An alert stores the observed value, threshold, baseline mean/std and z-score, so every incident is explainable.

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

Normal operation never reaches critical values: only incidents do, whether random or injected through `POST /api/simulation/incidents` (or the dashboard's incident panel).

## Port auditing

The scanner runs an asynchronous TCP connect scan with bounded concurrency and classifies each port as open, closed (RST) or filtered (timeout). On open ports it grabs service banners and escalates the risk of outdated versions such as old OpenSSH or vsFTPd 2.3.4. Host latency is measured over TCP, with an ICMP fallback. Each of the 44 catalogued services has a risk level, a reason and a remediation recommendation, and the audit gets a 0–100 risk score. Only private, loopback and link-local targets are allowed by default (`NETPULSE_SCAN_ALLOW_PUBLIC_TARGETS=false`), and at most 2 scans run concurrently.

## Installation

### Prerequisites

- **Python 3.11+** (3.12–3.14 tested) for the backend.
- **Node.js 20.19+** (22 or 24 recommended) for the dashboard.
- Optional: **Docker** with Compose v2.

### 1. Clone

```bash
git clone https://github.com/dftii/netpulse-sysguard.git
cd netpulse-sysguard
```

### 2. Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate              # Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env                # optional: tune NETPULSE_* settings
pytest                              # 225 tests
python seed.py                      # optional: 24 h demo dataset (--reset to rebuild)
python run.py                       # http://127.0.0.1:8000/docs
```

The seeder creates the same 8 servers as the simulator, 200 metric samples per server over the last 24 h, historical incidents of every type and port audits with critical findings. It is idempotent, and `--reset` only rebuilds the seeded servers' data.

### 3. Dashboard

In a second terminal:

```bash
cd frontend
npm install
npm run dev                         # http://localhost:5173
```

With the backend running, the dashboard connects to `http://127.0.0.1:8000` automatically. Without it, it starts the in-browser simulation. Switch at any time with the **Live backend / Demo simulation** selector in the header. Point to another backend with `VITE_API_BASE_URL` (see [frontend/.env.example](frontend/.env.example)).

Production build: `npm run build` (output in `frontend/dist`, served with `npm run preview`).

### 4. Docker (backend)

```bash
docker compose up -d --build                      # API on http://127.0.0.1:8000 (loopback only)
docker compose --profile seed run --rm seed       # optional: load the demo dataset
docker compose ps                                 # STATUS shows (healthy) once /api/health answers
```

The image is based on `python:3.12-slim`, runs as a non-root user, stores SQLite in the `netpulse-data` volume (`/app/data`) and checks `/api/health` with a `HEALTHCHECK`. It always runs a single uvicorn worker, because the telemetry pipeline, detector baselines and WebSocket clients live in process memory.

> **Telemetry inside a container.** `psutil` reads the kernel it runs on. Inside Docker the "host" node reports the container's view: its cgroup CPU/memory and, on Docker Desktop for Windows/macOS, the Linux VM, not your physical machine. Temperatures are usually unavailable. For real host telemetry, run natively with `python run.py`.

### 5. GitHub Pages

The [`deploy.yml`](.github/workflows/deploy.yml) workflow builds the dashboard with `VITE_DEFAULT_MODE=simulation` and publishes it on every push to `main` (or on demand from the Actions tab). Enable it once in **Settings → Pages → Build and deployment → Source: GitHub Actions**.

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
│   ├── run.py                        # Server entry point
│   ├── seed.py                       # Idempotent 24 h demo dataset seeder (--reset)
│   ├── Dockerfile                    # python:3.12-slim, non-root, healthcheck
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/               # header, servers, charts, ui, scanner, incidents, console
│   │   ├── hooks/useTelemetry.ts     # source lifecycle, rolling history, alerts, logs
│   │   ├── services/                 # TelemetrySource contract, REST/WS client, mode resolver
│   │   │   └── simulation/           # in-browser cluster simulator, detector and scanner
│   │   ├── lib/                      # formatting and load thresholds
│   │   ├── types/                    # TypeScript mirror of the backend schemas
│   │   └── App.tsx                   # NOC dashboard layout
│   └── vite.config.ts
├── .github/workflows/                # CI and GitHub Pages deployment
├── docker-compose.yml
├── LICENSE
└── README.md
```

## Configuration

All backend settings use the `NETPULSE_` prefix. See [backend/.env.example](backend/.env.example) for the full list, which covers telemetry interval, retention, detector thresholds, scanner limits and CORS origins. The dashboard reads `VITE_API_BASE_URL` and `VITE_DEFAULT_MODE` (`auto`, `backend` or `simulation`).

## Tech stack

**Backend:** Python 3.11+ · FastAPI · WebSockets · Pydantic v2 · SQLAlchemy 2.0 (async) · SQLite (WAL) · psutil · asyncio/socket · pytest

**Frontend:** React 19 · TypeScript (strict) · Vite 8 · Tailwind CSS 4 · Lucide icons · native SVG charts (no chart library)

**Ops:** Docker · Docker Compose · GitHub Actions · GitHub Pages

## License

MIT. See [LICENSE](LICENSE).
