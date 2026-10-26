/**
 * Contract implemented by both data sources:
 *  - BackendSource (services/backendSource.ts): FastAPI REST + /ws/telemetry.
 *  - SimulationSource (services/simulation/simulationSource.ts): in-browser live engine
 *    used automatically on static hosting such as GitHub Pages.
 * The UI only talks to this interface, so both modes behave identically.
 */

import type {
  AlertPage,
  AlertQuery,
  AnomalyAlertRead,
  IncidentInjectionRequest,
  IncidentInjectionResponse,
  NodeRead,
  PortAuditRead,
  PortAuditSummary,
  PortScanRequest,
  TelemetryBroadcast,
} from "../types/api";
import type { ConnectionMode, SourceStatus } from "../types/dashboard";

export type Unsubscribe = () => void;

export interface TelemetrySource {
  readonly mode: ConnectionMode;

  /** Begin streaming (idempotent). Frames arrive roughly once per second. */
  start(): void;
  /** Stop streaming and release sockets/timers (idempotent). */
  stop(): void;

  onFrame(listener: (frame: TelemetryBroadcast) => void): Unsubscribe;
  onStatus(listener: (status: SourceStatus) => void): Unsubscribe;
  getStatus(): SourceStatus;

  listNodes(): Promise<NodeRead[]>;
  listAlerts(query?: AlertQuery): Promise<AlertPage>;
  acknowledgeAlert(alertId: number): Promise<AnomalyAlertRead>;
  injectIncident(request: IncidentInjectionRequest): Promise<IncidentInjectionResponse>;
  /** Resolves with the full audit once the scan is complete; rejects with SourceError. */
  runPortScan(request: PortScanRequest, signal?: AbortSignal): Promise<PortAuditRead>;
  /** Recent audit headers (no findings), newest first. */
  listPortScans(limit?: number): Promise<PortAuditSummary[]>;
}

/** Error raised by any TelemetrySource operation; `status` mirrors the HTTP status when there is one. */
export class SourceError extends Error {
  readonly status: number | null;

  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = "SourceError";
    this.status = status;
  }
}
