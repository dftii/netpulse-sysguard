# NetPulse SysGuard - Frontend (Phase 2, planned)

This directory is a placeholder for the phase-2 web dashboard. The backend (FastAPI) is
complete in phase 1; the frontend has not been scaffolded yet, so there is no build,
dependency manifest or runnable code here at the moment.

## Planned stack

- **React 18** for the component model and UI state.
- **Vite** as the dev server and bundler.
- **TypeScript** for typed API contracts that mirror the backend Pydantic schemas.
- **TailwindCSS** for styling.
- **Recharts** for the live metric charts (CPU, memory, disk, latency, bandwidth).
- **WebSocket client** connecting to `ws://localhost:8000/ws/telemetry`. It receives one
  telemetry broadcast per tick containing the cluster summary, per-node snapshots and any
  newly raised anomaly alerts.

The REST API (served from `http://localhost:8000`) provides the data that the WebSocket
stream does not: alert history and acknowledgement, metric history, port audits, and
incident injection for the simulator.

## Planned folder layout

```
frontend/
├── public/            Static assets served as-is (favicon, logo)
├── src/
│   ├── components/    Reusable UI pieces: node cards, gauges, alert list, charts
│   ├── hooks/         Custom hooks, e.g. the telemetry WebSocket subscription
│   ├── pages/         Route-level views: cluster overview, node detail, port audit, alerts
│   ├── services/      HTTP and WebSocket clients for the backend API
│   └── types/         TypeScript types mirroring backend schemas and enums
└── (package.json, Vite and TypeScript configuration are added when phase 2 starts)
```

Each folder currently contains only a `.gitkeep` file so that Git tracks the empty
directories.
