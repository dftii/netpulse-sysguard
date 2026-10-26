/**
 * In-browser telemetry source. It runs the eight-node cluster simulator, the anomaly detector and a
 * simulated port auditor entirely client side and exposes them through the same TelemetrySource
 * contract as the FastAPI backend, so the dashboard behaves identically on static hosting.
 *
 * Pipeline per tick (same order as backend/app/main.py run_tick):
 *   engine.tick -> detector.analyze -> status escalation (OFFLINE is kept) -> summary -> frame.
 */

import {
  ANOMALY_TYPES,
  type AlertPage,
  type AlertQuery,
  type AnomalyAlertRead,
  type AnomalyType,
  type ClusterSummary,
  type IncidentInjectionRequest,
  type IncidentInjectionResponse,
  type NodeRead,
  type NodeStatus,
  type NodeTelemetry,
  type PortAuditRead,
  type PortAuditSummary,
  type PortScanRequest,
  type TelemetryBroadcast,
} from "../../types/api";
import type { ConnectionMode, SourceStatus } from "../../types/dashboard";
import { SourceError, type TelemetrySource, type Unsubscribe } from "../telemetrySource";
import { generateAlertHistory } from "./alertHistory";
import { AnomalyDetector, DEFAULT_DETECTOR_SETTINGS, type DetectorSettings } from "./detector";
import { ClusterEngine } from "./engine";
import { NODE_PROFILES, profileById, toNodeRead } from "./profiles";
import { Random, randomSeed } from "./random";
import { MAX_CONCURRENT_SCANS, SimulatedScanner, type ScanOutcome } from "./scanner";

export interface SimulationSourceOptions {
  /** Seed of the pseudo-random generator; omit for a different run on every page load. */
  seed?: number;
  /** Milliseconds between frames (default 1000). */
  intervalMs?: number;
  /** Probability per node per tick of a random incident (default 0.002, 0 disables them). */
  incidentProbability?: number;
  /** Amplitude multiplier of the short load bursts (default DEFAULT_BURST_SCALE; see ClusterEngineOptions). */
  burstScale?: number;
  /** Overrides of the detector thresholds (defaults: SIMULATION_DETECTOR_SETTINGS). */
  detectorSettings?: Partial<DetectorSettings>;
  /** Schedule one demo incident shortly after the first start() (default true). */
  demoIncident?: boolean;
  /** Multiplier of the simulated scan duration (default 1, 0 resolves scans immediately). */
  scanDelayScale?: number;
  /** Wall clock in epoch milliseconds (default Date.now); injectable for headless runs. */
  now?: () => number;
}

const DEFAULT_INTERVAL_MS = 1000;
const DEFAULT_INCIDENT_PROBABILITY = 0.002;
/** Burst amplitude relative to the backend profiles (1 = identical). */
export const DEFAULT_BURST_SCALE = 1;
/** Detector thresholds of the simulation: identical to the backend defaults (backend/app/config.py). */
export const SIMULATION_DETECTOR_SETTINGS: Readonly<DetectorSettings> = DEFAULT_DETECTOR_SETTINGS;
const PREWARM_TICKS = 90;
const DEMO_INCIDENT_MIN_TICKS = 15;
const DEMO_INCIDENT_MAX_TICKS = 25;
const DEMO_INCIDENT_MIN_SECONDS = 45;
const DEMO_INCIDENT_MAX_SECONDS = 75;
/** Incident kinds the detector flags within a few seconds, so the demo shows an alert quickly. */
const DEMO_INCIDENT_TYPES: readonly AnomalyType[] = [
  "cpu_spike",
  "thermal_spike",
  "critical_latency",
  "bandwidth_saturation",
  "service_down",
];
const MAX_STORED_ALERTS = 2000;
const MAX_STORED_AUDITS = 200;
const MIN_INCIDENT_SECONDS = 5;
const MAX_INCIDENT_SECONDS = 1800;
const DEFAULT_ALERT_PAGE_SIZE = 100;
const MAX_ALERT_PAGE_SIZE = 1000;
const DEFAULT_SCAN_LIST_SIZE = 50;
const MAX_SCAN_LIST_SIZE = 500;
const ENGINE_DETAIL = `In-browser simulation engine · ${NODE_PROFILES.length} nodes`;

function cloneAlert(alert: AnomalyAlertRead): AnomalyAlertRead {
  return { ...alert };
}

function cloneAudit(audit: PortAuditRead): PortAuditRead {
  return { ...audit, findings: audit.findings.map((finding) => ({ ...finding })) };
}

/** Same aggregation as backend build_summary. */
export function buildSummary(samples: readonly NodeTelemetry[], unacknowledgedAlerts: number): ClusterSummary {
  const total = samples.length;
  const counts: Record<NodeStatus, number> = { online: 0, warning: 0, critical: 0, offline: 0 };
  let cpu = 0;
  let memory = 0;
  let upload = 0;
  let download = 0;
  for (const sample of samples) {
    counts[sample.status] += 1;
    cpu += sample.cpu_percent;
    memory += sample.memory_percent;
    upload += sample.net_upload_kbps;
    download += sample.net_download_kbps;
  }
  const round2 = (value: number): number => Math.round(value * 100) / 100;
  return {
    total_nodes: total,
    online: counts.online,
    warning: counts.warning,
    critical: counts.critical,
    offline: counts.offline,
    avg_cpu_percent: total > 0 ? round2(cpu / total) : 0,
    avg_memory_percent: total > 0 ? round2(memory / total) : 0,
    total_upload_kbps: round2(upload),
    total_download_kbps: round2(download),
    unacknowledged_alerts: unacknowledgedAlerts,
  };
}

export class SimulationSource implements TelemetrySource {
  readonly mode: ConnectionMode = "simulation";

  private readonly intervalMs: number;
  private readonly now: () => number;
  private readonly rng: Random;
  private readonly engine: ClusterEngine;
  private readonly detector: AnomalyDetector;
  private readonly detectorSettings: DetectorSettings;
  private readonly scanner: SimulatedScanner;
  private readonly randomIncidentProbability: number;
  private readonly createdAt: string;

  private readonly frameListeners = new Set<(frame: TelemetryBroadcast) => void>();
  private readonly statusListeners = new Set<(status: SourceStatus) => void>();
  private status: SourceStatus;
  private timer: ReturnType<typeof setInterval> | null = null;

  private tick = 0;
  /** Latest per-node snapshots after status escalation (what the last frame carried). */
  private latestNodes: NodeTelemetry[] = [];
  private lastSeenAt: string | null = null;

  /** Alerts oldest first (ids ascend with detection time). */
  private alerts: AnomalyAlertRead[] = [];
  private readonly alertById = new Map<number, AnomalyAlertRead>();
  private unacknowledged = 0;
  private alertSeq = 0;

  private demoIncidentTick: number | null = null;
  private demoIncidentPending: boolean;

  private audits: PortAuditRead[] = [];
  private auditSeq = 0;
  private findingSeq = 0;
  private activeScans = 0;

  constructor(options: SimulationSourceOptions = {}) {
    this.intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
    if (!(this.intervalMs > 0)) {
      throw new RangeError("intervalMs must be greater than zero");
    }
    this.now = options.now ?? Date.now;
    this.rng = new Random(options.seed ?? randomSeed());
    this.randomIncidentProbability = options.incidentProbability ?? DEFAULT_INCIDENT_PROBABILITY;
    this.demoIncidentPending = options.demoIncident ?? true;
    this.createdAt = new Date(this.now()).toISOString();

    const intervalSeconds = this.intervalMs / 1000;
    this.engine = new ClusterEngine({
      rng: this.rng,
      intervalSeconds,
      incidentProbability: 0,
      burstScale: options.burstScale ?? DEFAULT_BURST_SCALE,
    });
    this.detectorSettings = {
      ...SIMULATION_DETECTOR_SETTINGS,
      telemetryIntervalSeconds: intervalSeconds,
      ...options.detectorSettings,
    };
    this.detector = new AnomalyDetector({ settings: this.detectorSettings, nextId: () => (this.alertSeq += 1) });
    this.scanner = new SimulatedScanner({ rng: this.rng, delayScale: options.scanDelayScale ?? 1, now: this.now });

    this.status = { mode: this.mode, phase: "stopped", detail: ENGINE_DETAIL, lastFrameAt: null };
    this.prewarm();
    this.seedAlertHistory();
    this.engine.setIncidentProbability(this.randomIncidentProbability);
  }

  // -- lifecycle ---------------------------------------------------------

  start(): void {
    if (this.timer !== null) {
      return;
    }
    if (this.demoIncidentPending) {
      this.demoIncidentPending = false;
      this.demoIncidentTick = this.tick + this.rng.int(DEMO_INCIDENT_MIN_TICKS, DEMO_INCIDENT_MAX_TICKS);
    }
    this.timer = setInterval(() => this.runScheduledTick(), this.intervalMs);
    this.setStatus({ phase: "live", detail: ENGINE_DETAIL });
    this.runScheduledTick();
  }

  stop(): void {
    if (this.timer === null) {
      return;
    }
    clearInterval(this.timer);
    this.timer = null;
    this.setStatus({ phase: "stopped", detail: `${ENGINE_DETAIL} · paused` });
  }

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
    return { ...this.status };
  }

  // -- tick pipeline -------------------------------------------------------

  /**
   * Advance the simulation by exactly one tick and return the frame (also delivered to listeners).
   * The interval timer calls this; headless callers can drive it directly with an injected clock.
   */
  advance(): TelemetryBroadcast {
    this.tick += 1;
    this.triggerDemoIncident();

    const at = new Date(this.now());
    const samples = this.engine.tick(at);

    const newAlerts: AnomalyAlertRead[] = [];
    for (const sample of samples) {
      for (const alert of this.detector.analyze(sample)) {
        newAlerts.push(alert);
      }
    }
    this.storeAlerts(newAlerts);

    const nodes = this.escalate(samples, newAlerts);
    this.latestNodes = nodes;
    this.lastSeenAt = at.toISOString();

    const frame: TelemetryBroadcast = {
      type: "telemetry",
      timestamp: this.lastSeenAt,
      tick: this.tick,
      summary: buildSummary(nodes, this.unacknowledged),
      nodes,
      new_alerts: newAlerts.map(cloneAlert),
    };
    this.deliver(frame);
    return frame;
  }

  private runScheduledTick(): void {
    try {
      this.advance();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.setStatus({ phase: "error", detail: `Simulation tick failed: ${message}` });
    }
  }

  private deliver(frame: TelemetryBroadcast): void {
    const firstFrame = this.status.lastFrameAt === null;
    const recovering = this.status.phase === "error";
    this.status.lastFrameAt = this.now();
    if (recovering) {
      this.setStatus({ phase: "live", detail: ENGINE_DETAIL });
    } else if (firstFrame) {
      this.emitStatus();
    }
    for (const listener of [...this.frameListeners]) {
      try {
        listener(frame);
      } catch (error) {
        console.error("Simulation frame listener failed", error);
      }
    }
  }

  /**
   * Alerts escalate the node status exactly like the backend: a critical alert makes the node
   * critical, a warning alert upgrades an online node, and an offline node stays offline.
   */
  private escalate(samples: readonly NodeTelemetry[], newAlerts: readonly AnomalyAlertRead[]): NodeTelemetry[] {
    const critical = new Set<number>();
    const warning = new Set<number>();
    for (const alert of newAlerts) {
      if (alert.severity === "critical") {
        critical.add(alert.node_id);
      } else if (alert.severity === "warning") {
        warning.add(alert.node_id);
      }
    }
    return samples.map((sample) => {
      if (sample.status === "offline") {
        return sample;
      }
      if (critical.has(sample.node_id) && sample.status !== "critical") {
        return { ...sample, status: "critical" };
      }
      if (warning.has(sample.node_id) && sample.status === "online") {
        return { ...sample, status: "warning" };
      }
      return sample;
    });
  }

  private triggerDemoIncident(): void {
    if (this.demoIncidentTick === null || this.tick < this.demoIncidentTick) {
      return;
    }
    this.demoIncidentTick = null;
    const idle = this.engine.hostnames.filter((hostname) => this.engine.activeIncident(hostname) === null);
    if (idle.length === 0) {
      return;
    }
    const hostname = this.rng.pick(idle);
    const kind = this.rng.pick(DEMO_INCIDENT_TYPES);
    const seconds = this.rng.int(DEMO_INCIDENT_MIN_SECONDS, DEMO_INCIDENT_MAX_SECONDS);
    this.engine.inject(hostname, kind, seconds);
  }

  // -- warm-up and history ---------------------------------------------------

  /** Fill the detector baselines with silent, backdated ticks so detection works immediately. */
  private prewarm(): void {
    const endMs = this.now();
    let last: NodeTelemetry[] = [];
    for (let index = 0; index < PREWARM_TICKS; index += 1) {
      const at = new Date(endMs - (PREWARM_TICKS - index) * this.intervalMs);
      last = this.engine.tick(at);
      for (const sample of last) {
        this.detector.analyze(sample);
      }
    }
    this.latestNodes = last;
    this.alertSeq = 0; // warm-up alerts (if any) are discarded together with their ids
  }

  private seedAlertHistory(): void {
    const history = generateAlertHistory(
      this.rng,
      this.now(),
      () => (this.alertSeq += 1),
      this.detectorSettings,
    );
    this.storeAlerts(history);
  }

  private storeAlerts(alerts: readonly AnomalyAlertRead[]): void {
    for (const alert of alerts) {
      this.alerts.push(alert);
      this.alertById.set(alert.id, alert);
      if (!alert.acknowledged) {
        this.unacknowledged += 1;
      }
    }
    const overflow = this.alerts.length - MAX_STORED_ALERTS;
    if (overflow > 0) {
      for (const dropped of this.alerts.splice(0, overflow)) {
        this.alertById.delete(dropped.id);
        if (!dropped.acknowledged) {
          this.unacknowledged -= 1;
        }
      }
    }
  }

  // -- REST-equivalent operations -------------------------------------------

  listNodes(): Promise<NodeRead[]> {
    const statusByNode = new Map(this.latestNodes.map((node) => [node.node_id, node.status]));
    return Promise.resolve(
      NODE_PROFILES.map((profile) =>
        toNodeRead(profile, statusByNode.get(profile.id) ?? "online", this.createdAt, this.lastSeenAt),
      ),
    );
  }

  listAlerts(query: AlertQuery = {}): Promise<AlertPage> {
    const limit = query.limit ?? DEFAULT_ALERT_PAGE_SIZE;
    const offset = query.offset ?? 0;
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_ALERT_PAGE_SIZE) {
      return Promise.reject(new SourceError(`limit must be between 1 and ${MAX_ALERT_PAGE_SIZE}`, 422));
    }
    if (!Number.isInteger(offset) || offset < 0) {
      return Promise.reject(new SourceError("offset must be zero or greater", 422));
    }

    const matches: AnomalyAlertRead[] = [];
    for (let index = this.alerts.length - 1; index >= 0; index -= 1) {
      const alert = this.alerts[index];
      if (alert === undefined) {
        continue;
      }
      if (query.node_id !== undefined && alert.node_id !== query.node_id) continue;
      if (query.severity !== undefined && alert.severity !== query.severity) continue;
      if (query.anomaly_type !== undefined && alert.anomaly_type !== query.anomaly_type) continue;
      if (query.acknowledged !== undefined && alert.acknowledged !== query.acknowledged) continue;
      matches.push(alert);
    }
    // Newest first: detection time, then id for alerts sharing a timestamp.
    matches.sort((a, b) => {
      const byTime = Date.parse(b.detected_at) - Date.parse(a.detected_at);
      return byTime !== 0 ? byTime : b.id - a.id;
    });
    return Promise.resolve({
      total: matches.length,
      limit,
      offset,
      items: matches.slice(offset, offset + limit).map(cloneAlert),
    });
  }

  acknowledgeAlert(alertId: number): Promise<AnomalyAlertRead> {
    const alert = this.alertById.get(alertId);
    if (alert === undefined) {
      return Promise.reject(new SourceError(`Alert ${alertId} not found`, 404));
    }
    if (!alert.acknowledged) {
      alert.acknowledged = true;
      alert.acknowledged_at = new Date(this.now()).toISOString();
      this.unacknowledged -= 1;
    }
    return Promise.resolve(cloneAlert(alert));
  }

  injectIncident(request: IncidentInjectionRequest): Promise<IncidentInjectionResponse> {
    const { hostname, anomaly_type: anomalyType, duration_seconds: duration } = request;
    if (!(ANOMALY_TYPES as readonly string[]).includes(anomalyType)) {
      return Promise.reject(new SourceError(`Unsupported anomaly type '${String(anomalyType)}'`, 422));
    }
    if (!Number.isInteger(duration) || duration < MIN_INCIDENT_SECONDS || duration > MAX_INCIDENT_SECONDS) {
      return Promise.reject(
        new SourceError(
          `duration_seconds must be an integer between ${MIN_INCIDENT_SECONDS} and ${MAX_INCIDENT_SECONDS}`,
          400,
        ),
      );
    }
    if (!this.engine.hasNode(hostname)) {
      return Promise.reject(new SourceError(`Unknown simulated node '${hostname}'`, 404));
    }
    this.engine.inject(hostname, anomalyType, duration);
    return Promise.resolve({ hostname, anomaly_type: anomalyType, duration_seconds: duration, accepted: true });
  }

  async runPortScan(request: PortScanRequest, signal?: AbortSignal): Promise<PortAuditRead> {
    const requestedNode = request.node_id ?? null;
    if (requestedNode !== null && profileById(requestedNode) === undefined) {
      throw new SourceError(`Node ${requestedNode} not found`, 404);
    }
    if (this.activeScans >= MAX_CONCURRENT_SCANS) {
      throw new SourceError(`${MAX_CONCURRENT_SCANS} scans already running; retry when one finishes`, 429);
    }

    this.activeScans += 1;
    let outcome: ScanOutcome;
    try {
      outcome = await this.scanner.scan(
        request,
        { isNodeOffline: (hostname) => this.engine.activeIncident(hostname) === "service_down" },
        signal,
      );
    } finally {
      this.activeScans -= 1;
    }

    this.auditSeq += 1;
    const auditId = this.auditSeq;
    const audit: PortAuditRead = {
      id: auditId,
      node_id: requestedNode ?? outcome.node?.id ?? null,
      target_host: outcome.targetHost,
      resolved_ip: outcome.resolvedIp,
      started_at: new Date(outcome.startedAtMs).toISOString(),
      finished_at: new Date(outcome.finishedAtMs).toISOString(),
      duration_ms: outcome.durationMs,
      host_reachable: outcome.hostReachable,
      host_latency_ms: outcome.hostLatencyMs,
      total_ports_scanned: outcome.totalPortsScanned,
      open_ports_count: outcome.findings.length,
      risk_score: outcome.riskScore,
      overall_risk: outcome.overallRisk,
      findings: outcome.findings.map((finding) => {
        this.findingSeq += 1;
        return {
          id: this.findingSeq,
          audit_id: auditId,
          port: finding.port,
          protocol: "tcp",
          service: finding.service,
          state: "open",
          banner: finding.banner,
          response_ms: finding.responseMs,
          risk_level: finding.riskLevel,
          risk_reason: finding.riskReason,
          recommendation: finding.recommendation,
        };
      }),
    };
    this.audits.push(audit);
    if (this.audits.length > MAX_STORED_AUDITS) {
      this.audits.splice(0, this.audits.length - MAX_STORED_AUDITS);
    }
    return cloneAudit(audit);
  }

  listPortScans(limit: number = DEFAULT_SCAN_LIST_SIZE): Promise<PortAuditSummary[]> {
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_SCAN_LIST_SIZE) {
      return Promise.reject(new SourceError(`limit must be between 1 and ${MAX_SCAN_LIST_SIZE}`, 422));
    }
    const summaries: PortAuditSummary[] = [];
    for (let index = this.audits.length - 1; index >= 0 && summaries.length < limit; index -= 1) {
      const audit = this.audits[index];
      if (audit === undefined) {
        continue;
      }
      const { findings: _findings, ...summary } = audit;
      summaries.push(summary);
    }
    return Promise.resolve(summaries);
  }

  // -- status ----------------------------------------------------------------

  private setStatus(patch: Partial<Pick<SourceStatus, "phase" | "detail">>): void {
    const next: SourceStatus = { ...this.status, ...patch };
    const changed = next.phase !== this.status.phase || next.detail !== this.status.detail;
    this.status = next;
    if (changed) {
      this.emitStatus();
    }
  }

  private emitStatus(): void {
    const snapshot = this.getStatus();
    for (const listener of [...this.statusListeners]) {
      try {
        listener(snapshot);
      } catch (error) {
        console.error("Simulation status listener failed", error);
      }
    }
  }
}
