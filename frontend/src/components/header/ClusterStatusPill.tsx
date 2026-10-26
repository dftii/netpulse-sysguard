/** Global cluster health pill derived from the latest telemetry summary. */

import type { ClusterSummary } from "../../types/api";
import type { SourcePhase } from "../../types/dashboard";
import { StatusDot } from "../ui/StatusDot";

export type ClusterState = "NOMINAL" | "ATTENTION" | "DEGRADED" | "OFFLINE";

interface ClusterStateStyle {
  dot: string;
  pill: string;
  pulse: boolean;
}

const STATE_STYLES: Record<ClusterState, ClusterStateStyle> = {
  NOMINAL: {
    dot: "bg-emerald-400",
    pill: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300 shadow-[0_0_20px_-8px_rgb(52_211_153/0.7)]",
    pulse: true,
  },
  ATTENTION: {
    dot: "bg-amber-400",
    pill: "border-amber-400/40 bg-amber-400/10 text-amber-300 shadow-[0_0_20px_-8px_rgb(251_191_36/0.7)]",
    pulse: true,
  },
  DEGRADED: {
    dot: "bg-rose-500",
    pill: "border-rose-500/50 bg-rose-500/10 text-rose-300 shadow-[0_0_22px_-6px_rgb(244_63_94/0.8)]",
    pulse: true,
  },
  OFFLINE: {
    dot: "bg-slate-500",
    pill: "border-slate-600/50 bg-slate-500/10 text-slate-400",
    pulse: false,
  },
};

/** Critical or unreachable nodes degrade the cluster, warnings only call for attention. */
export function deriveClusterState(summary: ClusterSummary | null, phase: SourcePhase): ClusterState {
  if (summary === null || phase === "error" || phase === "stopped") return "OFFLINE";
  if (summary.critical > 0 || summary.offline > 0) return "DEGRADED";
  if (summary.warning > 0) return "ATTENTION";
  return "NOMINAL";
}

export interface ClusterStatusPillProps {
  summary: ClusterSummary | null;
  phase: SourcePhase;
}

export function ClusterStatusPill({ summary, phase }: ClusterStatusPillProps) {
  const state = deriveClusterState(summary, phase);
  const style = STATE_STYLES[state];
  const detail =
    summary === null || state === "OFFLINE"
      ? "No telemetry"
      : `${summary.critical + summary.offline} critical · ${summary.warning} warning`;

  return (
    <div
      role="status"
      aria-label={`Cluster status ${state}. ${detail}.`}
      className={`inline-flex items-center gap-3 rounded-full border px-4 py-1.5 transition-colors duration-500 ${style.pill}`}
    >
      <StatusDot colorClass={style.dot} pulse={style.pulse} size="lg" />
      <span className="flex flex-col leading-tight">
        <span className="font-mono text-xs font-bold tracking-[0.22em]">{state}</span>
        <span className="font-mono text-[10px] tracking-wide opacity-70">{detail}</span>
      </span>
    </div>
  );
}
