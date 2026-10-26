/** Small helpers shared by the scan console, its terminal and the results view. */

import type { PortFindingRead, RiskLevel } from "../../types/api";

/** Highest risk first. */
export const RISK_ORDER: Record<RiskLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Left accent per risk level (literal class names so Tailwind can see them). */
export const RISK_ACCENT: Record<RiskLevel, string> = {
  critical: "border-l-rose-500",
  high: "border-l-amber-400",
  medium: "border-l-sky-400",
  low: "border-l-emerald-400",
  info: "border-l-slate-500",
};

/** Bar fill per risk level. */
export const RISK_BAR: Record<RiskLevel, string> = {
  critical: "bg-rose-500",
  high: "bg-amber-400",
  medium: "bg-sky-400",
  low: "bg-emerald-400",
  info: "bg-slate-500",
};

export function sortFindings(findings: readonly PortFindingRead[]): PortFindingRead[] {
  return [...findings].sort((a, b) => RISK_ORDER[a.risk_level] - RISK_ORDER[b.risk_level] || a.port - b.port);
}

/** "840 ms", "1.82 s", "1m 04s". */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(2)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.floor(seconds % 60);
  return `${minutes}m ${rest.toString().padStart(2, "0")}s`;
}

/** Elapsed seconds with one decimal for the live timer. */
export function formatElapsed(ms: number): string {
  return `${(ms / 1000).toFixed(1)}s`;
}
