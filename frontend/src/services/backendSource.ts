/**
 * TelemetrySource backed by the FastAPI service: live frames over /ws/telemetry plus the REST API.
 *
 * The socket layer reconnects with exponential backoff (1 s -> 15 s, jittered), keeps the connection
 * alive with an application-level ping every 20 s, drops silently dead connections, and never
 * reconnects after stop(). start()/stop() are idempotent so React StrictMode's mount/unmount/mount
 * cycle cannot leak sockets or timers.
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
import type { ConnectionMode, SourcePhase, SourceStatus } from "../types/dashboard";
import { alertQueryParams, ApiClient, toWebSocketUrl } from "./apiClient";
import type { TelemetrySource, Unsubscribe } from "./telemetrySource";

export const RECONNECT_INITIAL_DELAY_MS = 1_000;
export const RECONNECT_MAX_DELAY_MS = 15_000;
export const HEARTBEAT_INTERVAL_MS = 20_000;
/** The backend pushes a frame every second; this long without any traffic means the link is dead. */
export const STALE_CONNECTION_MS = 45_000;
export const SCAN_TIMEOUT_MS = 120_000;
/** After this many consecutive failed attempts the phase escalates from "reconnecting" to "error". */
const ERROR_AFTER_ATTEMPTS = 6;

/** Exponential backoff with +/-20 % jitter, capped at RECONNECT_MAX_DELAY_MS. `attempt` starts at 0. */
export function computeBackoffDelay(attempt: number, random: () => number = Math.random): number {
  const exponential = RECONNECT_INITIAL_DELAY_MS * 2 ** Math.min(attempt, 10);
  const capped = Math.min(RECONNECT_MAX_DELAY_MS, exponential);
  const jittered = capped * (0.8 + random() * 0.4);
  return Math.round(Math.min(RECONNECT_MAX_DELAY_MS, jittered));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTelemetryBroadcast(value: unknown): value is TelemetryBroadcast {
  return (
    isRecord(value) &&
    value.type === "telemetry" &&
    typeof value.tick === "number" &&
    typeof value.timestamp === "string" &&
    isRecord(value.summary) &&
    Array.isArray(value.nodes) &&
    Array.isArray(value.new_alerts)
  );
}

function describeClose(event: CloseEvent): string {
  const reason = event.reason.trim();
  return reason === "" ? `Connection closed (code ${event.code})` : `Connection closed (code ${event.code}: ${reason})`;
}

export class BackendSource implements TelemetrySource {
  readonly mode: ConnectionMode = "backend";

  private readonly api: ApiClient;
  private readonly wsUrl: string;
  private readonly frameListeners = new Set<(frame: TelemetryBroadcast) => void>();
  private readonly statusListeners = new Set<(status: SourceStatus) => void>();

  private status: SourceStatus;
  private socket: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private attempt = 0;
  private running = false;
  private lastActivityAt = 0;

  private readonly handleOnline = (): void => {
    if (!this.running || this.reconnectTimer === null) return;
    // The network just came back: skip the remaining backoff wait.
    this.attempt = 0;
    this.openSocket();
  };

  constructor(baseUrl: string) {
    this.api = new ApiClient(baseUrl);
    this.wsUrl = toWebSocketUrl(this.api.baseUrl);
    this.status = { mode: "backend", phase: "stopped", detail: "Not started", lastFrameAt: null };
  }

  // --- Lifecycle ------------------------------------------------------------

  start(): void {
    if (this.running) return;
    this.running = true;
    this.attempt = 0;
    this.status = { ...this.status, lastFrameAt: null };
    if (typeof window !== "undefined") window.addEventListener("online", this.handleOnline);
    this.openSocket();
  }

  stop(): void {
    this.running = false;
    this.clearReconnectTimer();
    this.stopHeartbeat();
    this.detachSocket();
    if (typeof window !== "undefined") window.removeEventListener("online", this.handleOnline);
    this.setStatus("stopped", "Stopped");
  }

  // --- Subscriptions --------------------------------------------------------

  onFrame(listener: (frame: TelemetryBroadcast) => void): Unsubscribe {
    this.frameListeners.add(listener);
    return () => {
      this.frameListeners.delete(listener);
    };
  }

  onStatus(listener: (status: SourceStatus) => void): Unsubscribe {
    this.statusListeners.add(listener);
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  getStatus(): SourceStatus {
    return this.status;
  }

  // --- REST -----------------------------------------------------------------

  listNodes(): Promise<NodeRead[]> {
    return this.api.get<NodeRead[]>("/api/nodes");
  }

  listAlerts(query?: AlertQuery): Promise<AlertPage> {
    return this.api.get<AlertPage>("/api/alerts", { query: alertQueryParams(query) });
  }

  acknowledgeAlert(alertId: number): Promise<AnomalyAlertRead> {
    return this.api.patch<AnomalyAlertRead>(`/api/alerts/${alertId}/acknowledge`);
  }

  injectIncident(request: IncidentInjectionRequest): Promise<IncidentInjectionResponse> {
    return this.api.post<IncidentInjectionResponse>("/api/simulation/incidents", request);
  }

  runPortScan(request: PortScanRequest, signal?: AbortSignal): Promise<PortAuditRead> {
    return this.api.post<PortAuditRead>("/api/scans", request, { timeoutMs: SCAN_TIMEOUT_MS, signal });
  }

  listPortScans(limit = 50): Promise<PortAuditSummary[]> {
    return this.api.get<PortAuditSummary[]>("/api/scans", { query: { limit } });
  }

  // --- WebSocket plumbing ---------------------------------------------------

  private openSocket(): void {
    this.clearReconnectTimer();
    this.detachSocket();

    if (this.attempt === 0) {
      this.setStatus("connecting", `Connecting to ${this.wsUrl}`);
    } else {
      this.setStatus("reconnecting", `Reconnecting to ${this.wsUrl} (attempt ${this.attempt})`);
    }

    let socket: WebSocket;
    try {
      socket = new WebSocket(this.wsUrl);
    } catch (error) {
      // An invalid URL cannot be fixed by retrying.
      this.running = false;
      if (typeof window !== "undefined") window.removeEventListener("online", this.handleOnline);
      const message = error instanceof Error ? error.message : String(error);
      this.setStatus("error", `Cannot open ${this.wsUrl}: ${message}`);
      return;
    }
    this.socket = socket;

    socket.onopen = () => {
      if (this.socket !== socket) return;
      this.attempt = 0;
      this.lastActivityAt = Date.now();
      this.startHeartbeat();
      this.setStatus("live", `Connected to ${this.wsUrl}`);
    };

    socket.onmessage = (event: MessageEvent<unknown>) => {
      if (this.socket !== socket) return;
      this.lastActivityAt = Date.now();
      if (typeof event.data !== "string") return;
      this.handleMessage(event.data);
    };

    socket.onclose = (event: CloseEvent) => {
      if (this.socket !== socket) return;
      this.socket = null;
      this.stopHeartbeat();
      if (!this.running) return;
      this.scheduleReconnect(describeClose(event));
    };
  }

  private handleMessage(raw: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return;
    }
    if (!isRecord(parsed)) return;
    // Pong replies (and any future control frames) only prove the link is alive.
    if (parsed.type !== "telemetry") return;
    if (!isTelemetryBroadcast(parsed)) return;

    // Updated silently so the per-second frame does not trigger a status notification.
    this.status = { ...this.status, lastFrameAt: Date.now() };
    for (const listener of [...this.frameListeners]) {
      try {
        listener(parsed);
      } catch (error) {
        console.error("Telemetry frame listener failed", error);
      }
    }
  }

  private scheduleReconnect(reason: string): void {
    const delay = computeBackoffDelay(this.attempt);
    this.attempt += 1;
    const phase: SourcePhase = this.attempt > ERROR_AFTER_ATTEMPTS ? "error" : "reconnecting";
    this.setStatus(phase, `${reason}. Retrying in ${(delay / 1000).toFixed(1)} s (attempt ${this.attempt})`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.running) this.openSocket();
    }, delay);
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      const socket = this.socket;
      if (socket === null || socket.readyState !== WebSocket.OPEN) return;
      if (Date.now() - this.lastActivityAt > STALE_CONNECTION_MS) {
        // Half-open connection: closing triggers the regular reconnect path through onclose.
        socket.close(4000, "stale connection");
        return;
      }
      try {
        socket.send("ping");
      } catch {
        // The socket is closing; onclose will drive the reconnect.
      }
    }, HEARTBEAT_INTERVAL_MS);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  /** Detaches every handler, then closes the socket without letting it trigger a reconnect. */
  private detachSocket(): void {
    const socket = this.socket;
    if (socket === null) return;
    this.socket = null;
    socket.onopen = null;
    socket.onmessage = null;
    socket.onclose = null;
    socket.onerror = null;
    if (socket.readyState === WebSocket.CONNECTING) {
      // Closing a CONNECTING socket makes browsers log a warning; wait for the handshake instead.
      socket.onopen = () => socket.close(1000, "client stopped");
    } else if (socket.readyState === WebSocket.OPEN) {
      socket.close(1000, "client stopped");
    }
  }

  private setStatus(phase: SourcePhase, detail: string): void {
    if (this.status.phase === phase && this.status.detail === detail) return;
    this.status = { ...this.status, phase, detail };
    for (const listener of [...this.statusListeners]) {
      try {
        listener(this.status);
      } catch (error) {
        console.error("Telemetry status listener failed", error);
      }
    }
  }
}
