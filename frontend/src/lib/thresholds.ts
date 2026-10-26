/**
 * Load thresholds shared by every component that colours a metric. They mirror the backend
 * classify_status() limits and the anomaly detector defaults (backend/app/config.py).
 */

import type { AlertSeverity, NodeStatus, RiskLevel } from "../types/api";

export type LoadLevel = "ok" | "warn" | "crit" | "idle";

export interface Threshold {
  warn: number;
  crit: number;
}

export const THRESHOLDS = {
  cpu: { warn: 75, crit: 90 },
  memory: { warn: 80, crit: 92 },
  disk: { warn: 85, crit: 95 },
  latencyMs: { warn: 120, crit: 250 },
  temperatureC: { warn: 80, crit: 90 },
  bandwidthPercent: { warn: 70, crit: 85 },
} as const satisfies Record<string, Threshold>;

export function loadLevel(value: number | null | undefined, threshold: Threshold): LoadLevel {
  if (value === null || value === undefined || Number.isNaN(value)) return "idle";
  if (value >= threshold.crit) return "crit";
  if (value >= threshold.warn) return "warn";
  return "ok";
}

/** Tailwind classes per load level: bar fill, text and soft background. */
export const LEVEL_STYLES: Record<LoadLevel, { bar: string; text: string; soft: string }> = {
  ok: { bar: "bg-emerald-400", text: "text-emerald-300", soft: "bg-emerald-400/10" },
  warn: { bar: "bg-amber-400", text: "text-amber-300", soft: "bg-amber-400/10" },
  crit: { bar: "bg-rose-500", text: "text-rose-300", soft: "bg-rose-500/10" },
  idle: { bar: "bg-slate-600", text: "text-slate-500", soft: "bg-slate-600/10" },
};

export const STATUS_STYLES: Record<NodeStatus, { dot: string; text: string; ring: string; label: string }> = {
  online: { dot: "bg-emerald-400", text: "text-emerald-300", ring: "ring-emerald-400/30", label: "ONLINE" },
  warning: { dot: "bg-amber-400", text: "text-amber-300", ring: "ring-amber-400/40", label: "WARNING" },
  critical: { dot: "bg-rose-500", text: "text-rose-300", ring: "ring-rose-500/50", label: "CRITICAL" },
  offline: { dot: "bg-slate-500", text: "text-slate-400", ring: "ring-slate-500/40", label: "OFFLINE" },
};

export const SEVERITY_STYLES: Record<AlertSeverity, { text: string; badge: string }> = {
  info: { text: "text-sky-300", badge: "bg-sky-500/15 text-sky-300 ring-sky-500/30" },
  warning: { text: "text-amber-300", badge: "bg-amber-500/15 text-amber-300 ring-amber-500/30" },
  critical: { text: "text-rose-300", badge: "bg-rose-500/15 text-rose-300 ring-rose-500/40" },
};

export const RISK_STYLES: Record<RiskLevel, { text: string; badge: string }> = {
  info: { text: "text-slate-300", badge: "bg-slate-500/15 text-slate-300 ring-slate-500/30" },
  low: { text: "text-emerald-300", badge: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30" },
  medium: { text: "text-sky-300", badge: "bg-sky-500/15 text-sky-300 ring-sky-500/30" },
  high: { text: "text-amber-300", badge: "bg-amber-500/15 text-amber-300 ring-amber-500/30" },
  critical: { text: "text-rose-300", badge: "bg-rose-500/15 text-rose-300 ring-rose-500/40" },
};
