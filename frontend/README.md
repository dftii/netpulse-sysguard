# NetPulse SysGuard: NOC dashboard

Single-page operations dashboard for the NetPulse SysGuard backend. It shows live telemetry
for a fleet of servers, audits open TCP ports, and surfaces anomaly alerts and incidents.
It runs in two data modes: against the FastAPI backend, or fully in the browser with a
built-in simulation engine, which is what the public GitHub Pages demo uses.

**Live demo:** https://dftii.github.io/netpulse-sysguard/ (always runs in simulation mode)

## Features

- **Header:** aggregate cluster KPIs and the data mode selector (Auto, Backend, Simulation).
- **Live server grid:** one card per node with status, CPU, memory, disk, temperature and
  uptime, colour-coded against the thresholds in `src/lib/thresholds.ts`.
- **Traffic and CPU charts:** rolling time series drawn with hand-written SVG. No chart
  library is used.
- **Port audit console:** starts TCP scans against an allowed target and shows open ports,
  service banners and latency as the scan completes.
- **Incident panel:** lists anomaly alerts (CPU spikes, memory leaks, bandwidth saturation,
  critical latency, disk pressure, service down, thermal spikes), lets you acknowledge them,
  and injects test incidents.
- **Live log console:** a streaming log of telemetry frames, alerts and operator actions.

## Data modes

The dashboard talks to data sources through one interface, `TelemetrySource`
(`src/services/telemetrySource.ts`). Two implementations sit behind it, so every panel behaves
the same in both modes.

| Mode | Data source | When it is used |
| --- | --- | --- |
| `backend` | REST API and `ws://…/ws/telemetry` on the FastAPI server | Forced, or detected by `auto` |
| `simulation` | In-browser engine (`src/services/simulation/`) | Forced, or fallback in `auto` |

Mode selection (`src/services/modeResolver.ts`):

1. `VITE_DEFAULT_MODE=backend` or `simulation` forces that mode at startup, without probing.
2. A host ending in `.github.io` goes straight to `simulation`, because a static site cannot
   reach a local backend.
3. A previous manual choice of `simulation` (stored in `localStorage` under `netpulse.mode`)
   is restored.
4. Otherwise the app probes `GET /api/health` with a 1.5 second timeout. If the backend
   answers, it uses `backend`; if not, it falls back to `simulation`. A stored `backend` choice
   is therefore only honoured while the backend is reachable.

The mode selector in the header switches source at any time (switching to `backend` probes
first) and remembers the choice for the next visit. A forced `VITE_DEFAULT_MODE` still wins on
startup.

## Stack

- React 19.3 and TypeScript 6
- Vite 8 (dev server and bundler)
- Tailwind CSS 4 (through `@tailwindcss/vite`)
- Lucide icons (`lucide-react`)
- No chart library: charts are native SVG

## Folder layout

```
frontend/
├── public/                     Static assets served as-is (favicon)
├── src/
│   ├── components/
│   │   ├── header/             Title bar, cluster KPIs, data mode selector
│   │   ├── servers/            Live server grid and per-node cards
│   │   ├── charts/             Native SVG traffic and CPU charts
│   │   ├── ui/                 Shared presentational primitives
│   │   ├── scanner/            Port audit console
│   │   ├── incidents/          Alert list, acknowledgement, incident injection
│   │   └── console/            Live log console
│   ├── hooks/
│   │   └── useTelemetry.ts     Subscribes components to the active TelemetrySource
│   ├── services/
│   │   ├── apiClient.ts        Typed fetch wrapper for the REST API
│   │   ├── backendSource.ts    TelemetrySource over REST and /ws/telemetry
│   │   ├── modeResolver.ts     Chooses backend or simulation mode
│   │   ├── telemetrySource.ts  Interface shared by both data sources
│   │   └── simulation/         In-browser telemetry engine
│   ├── lib/
│   │   ├── format.ts           Bandwidth, percent, latency, uptime and date formatting
│   │   └── thresholds.ts       Metric limits used for status colours
│   ├── types/
│   │   ├── api.ts              Types mirroring the backend schemas and enums
│   │   └── dashboard.ts        UI-only types
│   ├── App.tsx, main.tsx, index.css, vite-env.d.ts
├── .env.example                Documented environment variables (copy to .env.local)
├── index.html
├── vite.config.ts              base "./" so the build works under a sub-path
├── tsconfig.json, tsconfig.app.json, tsconfig.node.json
└── package.json
```

## Getting started

Requirements: Node.js 20.19 or newer (CI uses Node 22).

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. With the backend running (see the root `README.md`, typically
`python run.py` in `backend/` on http://127.0.0.1:8000), `auto` mode connects to it. Without
the backend, the dashboard uses the simulation engine.

The backend's default CORS list already allows `http://localhost:5173` and
`http://127.0.0.1:5173`. If you serve the frontend from another origin, add it to
`NETPULSE_CORS_ORIGINS` in `backend/.env`.

## Scripts

| Command | Description |
| --- | --- |
| `npm install` | Install dependencies from `package-lock.json` (use `npm ci` for a clean install) |
| `npm run dev` | Start the Vite dev server with hot reload on http://localhost:5173 |
| `npm run typecheck` | Run the TypeScript compiler in build mode without emitting files |
| `npm run build` | Type-check with `tsc -b`, then produce the production bundle in `dist/` |
| `npm run preview` | Serve the production bundle in `dist/` locally to test it before deploying |

## Environment variables

Vite reads variables from `frontend/.env.local`. Only variables prefixed with `VITE_` reach the
browser bundle, and everything in the bundle is public, so never store secrets there.

```bash
cp .env.example .env.local      # on Windows: copy .env.example .env.local
```

| Variable | Default | Description |
| --- | --- | --- |
| `VITE_API_BASE_URL` | `http://127.0.0.1:8000` | Backend origin for REST calls and the `/ws/telemetry` WebSocket |
| `VITE_DEFAULT_MODE` | `auto` | Startup mode: `auto`, `backend` or `simulation` |

See `.env.example` for the full description of each value.

## Deployment: GitHub Pages

The workflow `.github/workflows/deploy-pages.yml` builds the frontend and publishes `frontend/dist`
to GitHub Pages. It runs on every push to `main` that changes `frontend/**` or the workflow
file, and it can be started by hand from the Actions tab (`workflow_dispatch`).

One-time setup in the repository:

1. Open **Settings → Pages**.
2. Under **Build and deployment**, set **Source** to **GitHub Actions**.

The build sets `VITE_DEFAULT_MODE=simulation`, because GitHub Pages cannot reach a local
backend. `vite.config.ts` uses `base: "./"`, so the same bundle works under the project path
https://dftii.github.io/netpulse-sysguard/.

The workflow `.github/workflows/ci.yml` runs the backend tests and the frontend build on every
push and pull request to `main`.
