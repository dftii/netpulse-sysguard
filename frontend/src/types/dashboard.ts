/** Frontend-only state shapes shared by the data layer, the hooks and the UI components. */

import type {
  AnomalyAlertRead,
  IncidentInjectionRequest,
  NodeStatus,
  PortAuditRead,
  PortAuditSummary,
  PortScanRequest,
  TelemetryBroadcast,
} from "./api";

/** Where telemetry comes from: the FastAPI backend or the in-browser simulation engine. */
export type ConnectionMode = "backend" | "simulation";

/** Lifecycle of the active telemetry source. */
export type SourcePhase = "connecting" | "live" | "reconnecting" | "error" | "stopped";

export interface SourceStatus {
  mode: ConnectionMode;
  phase: SourcePhase;
  /** Human readable detail, e.g. "ws://127.0.0.1:8000/ws/telemetry" or the last error. */
  detail: string;
  /** Epoch milliseconds of the last frame received, or null before the first one. */
  lastFrameAt: number | null;
}

/** One per-second point of a node's rolling history (used by charts and sparklines). */
export interface NodeHistoryPoint {
  /** Epoch milliseconds. */
  t: number;
  cpu: number;
  memory: number;
  /** Upload + download in Mbps. */
  netMbps: number;
  latencyMs: number | null;
  temperatureC: number | null;
  status: NodeStatus;
}

/** One per-second point of cluster-wide aggregates. */
export interface ClusterHistoryPoint {
  t: number;
  avgCpu: number;
  uploadMbps: number;
  downloadMbps: number;
}

export type LogLevel = "debug" | "info" | "warn" | "error" | "critical";

export type LogSource = "telemetry" | "detector" | "scanner" | "system" | "operator";

/** One line of the live terminal-style log console. */
export interface LogEntry {
  /** Monotonic unique id (stable React key). */
  id: number;
  /** Epoch milliseconds. */
  t: number;
  level: LogLevel;
  source: LogSource;
  /** Hostname the event refers to, when there is one. */
  host: string | null;
  message: string;
}

/** Everything the dashboard renders, produced by the useTelemetry hook. */
export interface TelemetryState {
  status: SourceStatus;
  frame: TelemetryBroadcast | null;
  /** Rolling per-node history keyed by node_id, at most HISTORY_LENGTH points each. */
  nodeHistory: Record<number, NodeHistoryPoint[]>;
  clusterHistory: ClusterHistoryPoint[];
  /** Most recent alerts first, at most ALERT_BUFFER_LENGTH entries. */
  alerts: AnomalyAlertRead[];
  /** Oldest first, at most LOG_BUFFER_LENGTH entries. */
  logs: LogEntry[];
}

/** What the useTelemetry hook (hooks/useTelemetry.ts) returns to App.tsx. */
export interface TelemetryController {
  state: TelemetryState;
  /** Currently active mode. */
  mode: ConnectionMode;
  /** True while the initial backend probe is running (before the first source starts). */
  resolving: boolean;
  /** Result of the latest backend health probe: true reachable, false unreachable, null not probed yet. */
  backendAvailable: boolean | null;
  /** True when the mode was chosen automatically (no backend found / static hosting). */
  autoSelected: boolean;
  /** Switch source. Switching to "backend" re-probes /api/health first and logs the outcome. */
  setMode(mode: ConnectionMode): void;
  acknowledgeAlert(alertId: number): Promise<void>;
  injectIncident(request: IncidentInjectionRequest): Promise<void>;
  /** Runs the audit through the active source and writes scanner lines to the log console. */
  runPortScan(request: PortScanRequest, signal?: AbortSignal): Promise<PortAuditRead>;
  /** Recent port-audit headers (no findings), newest first, through the active source. */
  listPortScans(limit?: number): Promise<PortAuditSummary[]>;
  /** Append an operator/system line to the log console. */
  log(level: LogLevel, source: LogSource, message: string, host?: string | null): void;
  clearLogs(): void;
}

export const HISTORY_LENGTH = 120;
export const ALERT_BUFFER_LENGTH = 200;
export const LOG_BUFFER_LENGTH = 400;
