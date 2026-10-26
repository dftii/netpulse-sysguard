/**
 * Technical audit report: a point-in-time JSON snapshot of the cluster, its detected anomalies,
 * recent port audits and the operator log. Key names are snake_case to match the backend's own
 * JSON exports, and key order is fixed so two reports diff cleanly.
 *
 * buildAuditReport is pure (no clock, no DOM, no I/O); the only browser-bound helper is downloadJson.
 */

import {
  ALERT_SEVERITIES,
  ANOMALY_TYPES,
  type AlertSeverity,
  type AnomalyAlertRead,
  type AnomalyType,
  type ClusterSummary,
  type NodeStatus,
  type NodeTelemetry,
  type PortAuditSummary,
} from "../types/api";
import type {
  ConnectionMode,
  LogEntry,
  LogLevel,
  LogSource,
  NodeHistoryPoint,
  SourcePhase,
  TelemetryState,
} from "../types/dashboard";
import { HISTORY_LENGTH } from "../types/dashboard";
import { kbpsToMbps } from "./format";
import { loadLevel, THRESHOLDS, type LoadLevel } from "./thresholds";

export const REPORT_GENERATOR = "NetPulse SysGuard";
export const REPORT_VERSION = "1.0.0";
/** Maximum number of port audit headers included in a report. */
export const REPORT_PORT_AUDIT_LIMIT = 20;
/** Maximum number of operator log lines included in a report. */
export const REPORT_EVENT_LIMIT = 100;

export type OverallStatus = "nominal" | "attention" | "degraded" | "offline";

export interface NodeMetricLevels {
  cpu: LoadLevel;
  memory: LoadLevel;
  disk: LoadLevel;
  temperature: LoadLevel;
  latency: LoadLevel;
}

export interface NodeHistoryStats {
  window_seconds: number;
  samples: number;
  cpu_percent: { min: number | null; avg: number | null; max: number | null };
  net_mbps: { avg: number | null; max: number | null };
}

export interface AuditReportNode {
  node_id: number;
  hostname: string;
  display_name: string;
  role: NodeTelemetry["role"];
  ip_address: string;
  is_simulated: boolean;
  status: NodeStatus;
  simulated_incident: AnomalyType | null;
  timestamp: string;
  uptime_seconds: number;
  metrics: {
    cpu_percent: number;
    memory_percent: number;
    memory_used_mb: number;
    memory_total_mb: number;
    disk_percent: number;
    latency_ms: number | null;
    temperature_c: number | null;
    net_upload_kbps: number;
    net_download_kbps: number;
    link_capacity_mbps: number;
    process_count: number;
  };
  levels: NodeMetricLevels;
  history: NodeHistoryStats;
}

export interface AuditReportEvent {
  t: string;
  level: LogLevel;
  source: LogSource;
  host: string | null;
  message: string;
}

export interface AuditReport {
  report: {
    generator: string;
    version: string;
    generated_at: string;
    data_source: ConnectionMode;
    source_detail: string;
    telemetry_tick: number | null;
  };
  cluster: {
    overall_status: OverallStatus;
    summary: ClusterSummary | null;
    totals: {
      bandwidth_mbps: number | null;
      avg_uptime_seconds: number | null;
    };
  };
  nodes: AuditReportNode[];
  anomalies: {
    total: number;
    by_severity: Record<AlertSeverity, number>;
    by_type: Record<AnomalyType, number>;
    unacknowledged: number;
    items: AnomalyAlertRead[];
  };
  port_audits: {
    note: string;
    error: string | null;
    items: PortAuditSummary[];
  };
  recent_events: AuditReportEvent[];
}

export interface AuditReportInput {
  state: TelemetryState;
  mode: ConnectionMode;
  /** Recent audit headers, or null when they could not be listed. */
  portScans: PortAuditSummary[] | null;
  /** Why the audits could not be listed; ignored when portScans is provided. */
  portScansError?: string | null;
  generatedAt: Date;
}

const PORT_AUDIT_NOTE =
  "Audit headers only: per-port findings are omitted. Run a scan from the Port Scanner panel to inspect individual ports.";

function round(value: number, digits = 2): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

/** Same rule as the header status pill, expressed with lowercase labels. */
function deriveOverallStatus(summary: ClusterSummary | null, phase: SourcePhase): OverallStatus {
  if (summary === null || phase === "error" || phase === "stopped") return "offline";
  if (summary.critical > 0 || summary.offline > 0) return "degraded";
  if (summary.warning > 0) return "attention";
  return "nominal";
}

function summariseHistory(points: readonly NodeHistoryPoint[] | undefined): NodeHistoryStats {
  const window = { window_seconds: HISTORY_LENGTH };
  if (points === undefined || points.length === 0) {
    return {
      ...window,
      samples: 0,
      cpu_percent: { min: null, avg: null, max: null },
      net_mbps: { avg: null, max: null },
    };
  }
  let cpuMin = Number.POSITIVE_INFINITY;
  let cpuMax = Number.NEGATIVE_INFINITY;
  let cpuSum = 0;
  let netMax = Number.NEGATIVE_INFINITY;
  let netSum = 0;
  for (const point of points) {
    cpuMin = Math.min(cpuMin, point.cpu);
    cpuMax = Math.max(cpuMax, point.cpu);
    cpuSum += point.cpu;
    netMax = Math.max(netMax, point.netMbps);
    netSum += point.netMbps;
  }
  return {
    ...window,
    samples: points.length,
    cpu_percent: { min: round(cpuMin), avg: round(cpuSum / points.length), max: round(cpuMax) },
    net_mbps: { avg: round(netSum / points.length, 3), max: round(netMax, 3) },
  };
}

function buildNode(node: NodeTelemetry, history: readonly NodeHistoryPoint[] | undefined): AuditReportNode {
  return {
    node_id: node.node_id,
    hostname: node.hostname,
    display_name: node.display_name,
    role: node.role,
    ip_address: node.ip_address,
    is_simulated: node.is_simulated,
    status: node.status,
    simulated_incident: node.simulated_incident,
    timestamp: node.timestamp,
    uptime_seconds: node.uptime_seconds,
    metrics: {
      cpu_percent: node.cpu_percent,
      memory_percent: node.memory_percent,
      memory_used_mb: node.memory_used_mb,
      memory_total_mb: node.memory_total_mb,
      disk_percent: node.disk_percent,
      latency_ms: node.latency_ms,
      temperature_c: node.temperature_c,
      net_upload_kbps: node.net_upload_kbps,
      net_download_kbps: node.net_download_kbps,
      link_capacity_mbps: node.link_capacity_mbps,
      process_count: node.process_count,
    },
    levels: {
      cpu: loadLevel(node.cpu_percent, THRESHOLDS.cpu),
      memory: loadLevel(node.memory_percent, THRESHOLDS.memory),
      disk: loadLevel(node.disk_percent, THRESHOLDS.disk),
      temperature: loadLevel(node.temperature_c, THRESHOLDS.temperatureC),
      latency: loadLevel(node.latency_ms, THRESHOLDS.latencyMs),
    },
    history: summariseHistory(history),
  };
}

function countBy<K extends string>(keys: readonly K[], values: readonly K[]): Record<K, number> {
  const counts = Object.fromEntries(keys.map((key) => [key, 0])) as Record<K, number>;
  for (const value of values) counts[value] += 1;
  return counts;
}

function buildEvent(entry: LogEntry): AuditReportEvent {
  return {
    t: new Date(entry.t).toISOString(),
    level: entry.level,
    source: entry.source,
    host: entry.host,
    message: entry.message,
  };
}

export function buildAuditReport(input: AuditReportInput): AuditReport {
  const { state, mode, portScans, portScansError = null, generatedAt } = input;
  const { frame, alerts, logs, nodeHistory, status } = state;
  const summary = frame?.summary ?? null;
  const nodes = frame?.nodes ?? [];

  const activeNodes = nodes.filter((node) => node.status !== "offline");
  const avgUptime =
    activeNodes.length === 0
      ? null
      : round(activeNodes.reduce((sum, node) => sum + node.uptime_seconds, 0) / activeNodes.length, 0);

  return {
    report: {
      generator: REPORT_GENERATOR,
      version: REPORT_VERSION,
      generated_at: generatedAt.toISOString(),
      data_source: mode,
      source_detail: status.detail,
      telemetry_tick: frame?.tick ?? null,
    },
    cluster: {
      overall_status: deriveOverallStatus(summary, status.phase),
      summary,
      totals: {
        bandwidth_mbps:
          summary === null ? null : round(kbpsToMbps(summary.total_upload_kbps + summary.total_download_kbps), 3),
        avg_uptime_seconds: avgUptime,
      },
    },
    nodes: nodes.map((node) => buildNode(node, nodeHistory[node.node_id])),
    anomalies: {
      total: alerts.length,
      by_severity: countBy(
        ALERT_SEVERITIES,
        alerts.map((alert) => alert.severity),
      ),
      by_type: countBy(
        ANOMALY_TYPES,
        alerts.map((alert) => alert.anomaly_type),
      ),
      unacknowledged: alerts.filter((alert) => !alert.acknowledged).length,
      items: alerts,
    },
    port_audits: {
      note: PORT_AUDIT_NOTE,
      error: portScans === null ? (portScansError ?? "Port audits could not be listed") : null,
      items: portScans === null ? [] : portScans.slice(0, REPORT_PORT_AUDIT_LIMIT),
    },
    recent_events: logs.slice(-REPORT_EVENT_LIMIT).map(buildEvent),
  };
}

/** "netpulse-audit-report-20261026-140327.json", using the UTC clock so reports sort across time zones. */
export function auditReportFilename(date: Date): string {
  const pad = (n: number): string => n.toString().padStart(2, "0");
  const day = `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}`;
  const time = `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}`;
  return `netpulse-audit-report-${day}-${time}.json`;
}

/** Serialises `data` as pretty-printed JSON and triggers a browser download. */
export function downloadJson(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  try {
    anchor.click();
  } finally {
    anchor.remove();
    // Revoke on the next task so the browser has already started consuming the blob.
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}
