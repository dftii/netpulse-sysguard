/** Key performance indicator tile: icon, label, headline value, caption and optional visual. */

import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export type KpiTone = "neutral" | "ok" | "warn" | "crit";

const TONE_STYLES: Record<KpiTone, { tile: string; value: string; frame: string }> = {
  neutral: {
    tile: "bg-noc-accent/10 text-noc-accent ring-noc-accent/30",
    value: "text-slate-100",
    frame: "",
  },
  ok: {
    tile: "bg-emerald-400/10 text-emerald-300 ring-emerald-400/30",
    value: "text-emerald-300",
    frame: "",
  },
  warn: {
    tile: "bg-amber-400/10 text-amber-300 ring-amber-400/30",
    value: "text-amber-300",
    frame: "border-amber-400/30",
  },
  crit: {
    tile: "bg-rose-500/10 text-rose-300 ring-rose-500/40",
    value: "text-rose-300",
    frame: "border-rose-500/40 shadow-[0_0_24px_-10px_rgb(244_63_94/0.6)]",
  },
};

export interface KpiCardProps {
  label: string;
  icon: LucideIcon;
  /** Headline value, already formatted. */
  value: string;
  /** Small unit rendered next to the value. */
  unit?: string;
  caption?: ReactNode;
  tone?: KpiTone;
  /** Optional visual under the caption, e.g. a sparkline or a stacked bar. */
  children?: ReactNode;
}

export function KpiCard({ label, icon: Icon, value, unit, caption, tone = "neutral", children }: KpiCardProps) {
  const style = TONE_STYLES[tone];
  return (
    <div role="group" aria-label={label} className={`noc-panel flex min-w-0 flex-col gap-2 p-4 ${style.frame}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-[11px] font-semibold tracking-[0.16em] text-slate-400 uppercase">{label}</span>
        <span className={`grid size-8 shrink-0 place-items-center rounded-lg ring-1 ring-inset ${style.tile}`}>
          <Icon className="size-4" aria-hidden="true" />
        </span>
      </div>
      <div className="flex items-baseline gap-1.5">
        <span className={`font-mono text-2xl leading-none font-semibold tabular-nums ${style.value}`}>{value}</span>
        {unit ? <span className="font-mono text-xs text-slate-500">{unit}</span> : null}
      </div>
      {caption ? <div className="min-h-4 text-[11px] text-slate-500">{caption}</div> : null}
      {children ? <div className="mt-auto pt-1">{children}</div> : null}
    </div>
  );
}
