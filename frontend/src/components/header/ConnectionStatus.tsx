/** Telemetry link indicator: phase, active source, endpoint detail and time since the last frame. */

import { Radio, Wifi, WifiOff } from "lucide-react";
import type { ConnectionMode, SourcePhase, SourceStatus } from "../../types/dashboard";
import { StatusDot } from "../ui/StatusDot";
import { useNow } from "./useNow";

interface PhaseStyle {
  label: string;
  dot: string;
  text: string;
  pulse: boolean;
}

const PHASE_STYLES: Record<SourcePhase, PhaseStyle> = {
  live: { label: "LIVE", dot: "bg-emerald-400", text: "text-emerald-300", pulse: true },
  connecting: { label: "CONNECTING", dot: "bg-sky-400", text: "text-sky-300", pulse: true },
  reconnecting: { label: "RECONNECTING", dot: "bg-amber-400", text: "text-amber-300", pulse: true },
  error: { label: "ERROR", dot: "bg-rose-500", text: "text-rose-300", pulse: false },
  stopped: { label: "STOPPED", dot: "bg-slate-500", text: "text-slate-400", pulse: false },
};

export const MODE_LABELS: Record<ConnectionMode, string> = {
  backend: "Live backend",
  simulation: "Demo simulation",
};

/** Seconds without a frame after which the link is flagged as stale. */
const STALE_AFTER_SECONDS = 5;

export interface ConnectionStatusProps {
  status: SourceStatus;
}

export function ConnectionStatus({ status }: ConnectionStatusProps) {
  const now = useNow(1000);
  const style = PHASE_STYLES[status.phase];
  const Icon = status.phase === "live" ? Wifi : status.phase === "error" || status.phase === "stopped" ? WifiOff : Radio;

  const secondsSince =
    status.lastFrameAt === null ? null : Math.max(0, Math.floor((now - status.lastFrameAt) / 1000));
  const stale = secondsSince !== null && secondsSince >= STALE_AFTER_SECONDS;
  const lastFrameLabel =
    secondsSince === null ? "no frames yet" : secondsSince === 0 ? "last frame just now" : `last frame ${secondsSince}s ago`;

  return (
    <div className="flex min-w-0 items-center gap-3" role="status" aria-live="polite">
      <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-slate-800/60 ring-1 ring-inset ring-slate-700/60">
        <Icon className={`size-4 ${style.text}`} aria-hidden="true" />
      </span>
      <div className="min-w-0 leading-tight">
        <div className="flex items-center gap-2 font-mono text-xs font-semibold">
          <StatusDot colorClass={style.dot} pulse={style.pulse} />
          <span className={`tracking-[0.18em] ${style.text}`}>{style.label}</span>
          <span className="text-slate-500">·</span>
          <span className="text-slate-300">{MODE_LABELS[status.mode]}</span>
        </div>
        <div className="mt-0.5 flex min-w-0 items-center gap-2 font-mono text-[11px] text-slate-500">
          <span className="truncate" title={status.detail}>
            {status.detail || "—"}
          </span>
          <span className="shrink-0 text-slate-700" aria-hidden="true">
            |
          </span>
          <span className={`shrink-0 tabular-nums ${stale ? "text-amber-400" : ""}`}>{lastFrameLabel}</span>
        </div>
      </div>
    </div>
  );
}
