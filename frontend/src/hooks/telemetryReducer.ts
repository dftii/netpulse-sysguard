/**
 * Pure state machine behind useTelemetry. Every incoming frame is folded into history buffers,
 * the alert list and the log console by a single reducer action, so the dashboard re-renders once
 * per frame. The reducer is deterministic (timestamps come from the actions) and therefore safe
 * under React StrictMode's double invocation.
 */

import { formatBandwidth, formatPercent } from "../lib/format";
import type { AlertSeverity, AnomalyAlertRead, NodeStatus, NodeTelemetry, TelemetryBroadcast } from "../types/api";
import {
  ALERT_BUFFER_LENGTH,
  HISTORY_LENGTH,
  LOG_BUFFER_LENGTH,
  type ClusterHistoryPoint,
  type ConnectionMode,
  type LogEntry,
  type LogLevel,
  type LogSource,
  type NodeHistoryPoint,
  type SourceStatus,
  type TelemetryState,
} from "../types/dashboard";

/** A heartbeat debug line is written every this many ticks. */
export const HEARTBEAT_EVERY_TICKS = 15;

export interface LogDraft {
  level: LogLevel;
  source: LogSource;
  host: string | null;
  message: string;
}

export interface TelemetryReducerState {
  view: TelemetryState;
  nextLogId: number;
  lastHeartbeatTick: number | null;
}

export type TelemetryAction =
  | { type: "reset"; mode: ConnectionMode }
  | { type: "frame"; frame: TelemetryBroadcast; status: SourceStatus; now: number }
  | { type: "status"; status: SourceStatus; now: number }
  | { type: "alertsLoaded"; alerts: AnomalyAlertRead[] }
  | { type: "alertUpdated"; alert: AnomalyAlertRead }
  | { type: "log"; drafts: LogDraft[]; now: number }
  | { type: "clearLogs" };

const NODE_STATUS_LEVEL: Record<NodeStatus, LogLevel> = {
  online: "info",
  warning: "warn",
  critical: "critical",
  offline: "error",
};

const SEVERITY_LEVEL: Record<AlertSeverity, LogLevel> = {
  info: "info",
  warning: "warn",
  critical: "critical",
};

export function createInitialState(): TelemetryReducerState {
  return {
    view: {
      status: { mode: "simulation", phase: "connecting", detail: "Resolving data source…", lastFrameAt: null },
      frame: null,
      nodeHistory: {},
      clusterHistory: [],
      alerts: [],
      logs: [],
    },
    nextLogId: 1,
    lastHeartbeatTick: null,
  };
}

/** Appends `items` to `list`, dropping the oldest entries beyond `cap`. */
function appendCapped<T>(list: readonly T[], items: readonly T[], cap: number): T[] {
  const merged = [...list, ...items];
  return merged.length > cap ? merged.slice(merged.length - cap) : merged;
}

function appendLogs(state: TelemetryReducerState, drafts: readonly LogDraft[], now: number): TelemetryReducerState {
  if (drafts.length === 0) return state;
  let nextId = state.nextLogId;
  const entries: LogEntry[] = drafts.map((draft) => ({ id: nextId++, t: now, ...draft }));
  return {
    ...state,
    nextLogId: nextId,
    view: { ...state.view, logs: appendCapped(state.view.logs, entries, LOG_BUFFER_LENGTH) },
  };
}

function parseTimestamp(iso: string, fallback: number): number {
  const parsed = Date.parse(iso);
  return Number.isNaN(parsed) ? fallback : parsed;
}

/** Newest first: by detection time, then by id. */
function compareAlertsDescending(a: AnomalyAlertRead, b: AnomalyAlertRead): number {
  const byTime = Date.parse(b.detected_at) - Date.parse(a.detected_at);
  if (Number.isNaN(byTime) || byTime === 0) return b.id - a.id;
  return byTime;
}

function describeStatusChange(status: SourceStatus): LogDraft {
  const mode = status.mode === "backend" ? "backend" : "simulation";
  switch (status.phase) {
    case "connecting":
      return { level: "info", source: "system", host: null, message: `Connecting (${mode}): ${status.detail}` };
    case "live":
      return { level: "info", source: "system", host: null, message: `Telemetry stream live (${mode}): ${status.detail}` };
    case "reconnecting":
      return { level: "warn", source: "system", host: null, message: `Telemetry stream interrupted: ${status.detail}` };
    case "error":
      return { level: "error", source: "system", host: null, message: `Telemetry source error: ${status.detail}` };
    case "stopped":
      return { level: "info", source: "system", host: null, message: `Telemetry source stopped (${mode})` };
  }
}

function nodePoint(node: NodeTelemetry, t: number): NodeHistoryPoint {
  return {
    t,
    cpu: node.cpu_percent,
    memory: node.memory_percent,
    netMbps: (node.net_upload_kbps + node.net_download_kbps) / 1000,
    latencyMs: node.latency_ms,
    temperatureC: node.temperature_c,
    status: node.status,
  };
}

function statusTransitionLogs(previous: TelemetryBroadcast | null, frame: TelemetryBroadcast): LogDraft[] {
  if (previous === null) return [];
  const before = new Map<number, NodeStatus>();
  for (const node of previous.nodes) before.set(node.node_id, node.status);
  const drafts: LogDraft[] = [];
  for (const node of frame.nodes) {
    const old = before.get(node.node_id);
    if (old === undefined || old === node.status) continue;
    drafts.push({
      level: NODE_STATUS_LEVEL[node.status],
      source: "telemetry",
      host: node.hostname,
      message: `${node.hostname} ${old.toUpperCase()} → ${node.status.toUpperCase()}`,
    });
  }
  return drafts;
}

function alertLogs(alerts: readonly AnomalyAlertRead[], frame: TelemetryBroadcast): LogDraft[] {
  const hostById = new Map<number, string>();
  for (const node of frame.nodes) hostById.set(node.node_id, node.hostname);
  return alerts.map((alert) => ({
    level: SEVERITY_LEVEL[alert.severity],
    source: "detector",
    host: alert.node_hostname ?? hostById.get(alert.node_id) ?? null,
    message: `[${alert.anomaly_type.toUpperCase()}] ${alert.message}`,
  }));
}

function heartbeatLog(frame: TelemetryBroadcast): LogDraft {
  const { summary } = frame;
  const throughput = formatBandwidth(summary.total_upload_kbps + summary.total_download_kbps);
  return {
    level: "debug",
    source: "system",
    host: null,
    message: `tick ${frame.tick} · ${frame.nodes.length} nodes · avg cpu ${formatPercent(summary.avg_cpu_percent)} · ${throughput}`,
  };
}

function applyFrame(
  state: TelemetryReducerState,
  frame: TelemetryBroadcast,
  status: SourceStatus,
  now: number,
): TelemetryReducerState {
  const previous = state.view.frame;
  if (previous !== null && previous.tick === frame.tick && previous.timestamp === frame.timestamp) {
    // The backend replays its latest frame on connect; ignore an exact duplicate.
    return { ...state, view: { ...state.view, status } };
  }

  const t = parseTimestamp(frame.timestamp, now);

  const nodeHistory: Record<number, NodeHistoryPoint[]> = { ...state.view.nodeHistory };
  for (const node of frame.nodes) {
    nodeHistory[node.node_id] = appendCapped(nodeHistory[node.node_id] ?? [], [nodePoint(node, t)], HISTORY_LENGTH);
  }

  const clusterPoint: ClusterHistoryPoint = {
    t,
    avgCpu: frame.summary.avg_cpu_percent,
    uploadMbps: frame.summary.total_upload_kbps / 1000,
    downloadMbps: frame.summary.total_download_kbps / 1000,
  };

  let alerts = state.view.alerts;
  let freshAlerts: AnomalyAlertRead[] = [];
  if (frame.new_alerts.length > 0) {
    const known = new Set(alerts.map((alert) => alert.id));
    freshAlerts = frame.new_alerts.filter((alert) => {
      if (known.has(alert.id)) return false;
      known.add(alert.id);
      return true;
    });
    if (freshAlerts.length > 0) {
      freshAlerts = [...freshAlerts].sort(compareAlertsDescending);
      alerts = [...freshAlerts, ...alerts].slice(0, ALERT_BUFFER_LENGTH);
    }
  }

  const drafts: LogDraft[] = [...statusTransitionLogs(previous, frame), ...alertLogs(freshAlerts, frame)];
  let lastHeartbeatTick = state.lastHeartbeatTick;
  if (lastHeartbeatTick === null || frame.tick < lastHeartbeatTick || frame.tick - lastHeartbeatTick >= HEARTBEAT_EVERY_TICKS) {
    drafts.push(heartbeatLog(frame));
    lastHeartbeatTick = frame.tick;
  }

  const next: TelemetryReducerState = {
    ...state,
    lastHeartbeatTick,
    view: {
      ...state.view,
      status,
      frame,
      nodeHistory,
      clusterHistory: appendCapped(state.view.clusterHistory, [clusterPoint], HISTORY_LENGTH),
      alerts,
    },
  };
  return appendLogs(next, drafts, now);
}

export function telemetryReducer(state: TelemetryReducerState, action: TelemetryAction): TelemetryReducerState {
  switch (action.type) {
    case "reset":
      return {
        ...state,
        lastHeartbeatTick: null,
        view: {
          ...state.view,
          status: { mode: action.mode, phase: "stopped", detail: "Starting…", lastFrameAt: null },
          frame: null,
          nodeHistory: {},
          clusterHistory: [],
          alerts: [],
        },
      };

    case "frame":
      return applyFrame(state, action.frame, action.status, action.now);

    case "status": {
      const previous = state.view.status;
      const changed = previous.phase !== action.status.phase || previous.mode !== action.status.mode;
      const next: TelemetryReducerState = { ...state, view: { ...state.view, status: action.status } };
      return changed ? appendLogs(next, [describeStatusChange(action.status)], action.now) : next;
    }

    case "alertsLoaded": {
      const incomingIds = new Set(action.alerts.map((alert) => alert.id));
      const retained = state.view.alerts.filter((alert) => !incomingIds.has(alert.id));
      const merged = [...action.alerts, ...retained].sort(compareAlertsDescending).slice(0, ALERT_BUFFER_LENGTH);
      return { ...state, view: { ...state.view, alerts: merged } };
    }

    case "alertUpdated":
      return {
        ...state,
        view: {
          ...state.view,
          alerts: state.view.alerts.map((alert) => (alert.id === action.alert.id ? action.alert : alert)),
        },
      };

    case "log":
      return appendLogs(state, action.drafts, action.now);

    case "clearLogs":
      return { ...state, view: { ...state.view, logs: [] } };
  }
}
