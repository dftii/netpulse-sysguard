/** Compact uppercase label with a tinted background and an inset ring. */

import type { ReactNode } from "react";

export type BadgeTone = "ok" | "warn" | "crit" | "idle" | "info" | "accent";

const TONE_CLASSES: Record<BadgeTone, string> = {
  ok: "bg-emerald-400/10 text-emerald-300 ring-emerald-400/30",
  warn: "bg-amber-400/10 text-amber-300 ring-amber-400/30",
  crit: "bg-rose-500/10 text-rose-300 ring-rose-500/40",
  idle: "bg-slate-500/10 text-slate-400 ring-slate-500/30",
  info: "bg-sky-500/10 text-sky-300 ring-sky-500/30",
  accent: "bg-noc-accent/10 text-cyan-200 ring-noc-accent/30",
};

export interface BadgeProps {
  tone: BadgeTone;
  children: ReactNode;
  /** Optional leading element such as a StatusDot or an icon. */
  leading?: ReactNode;
  className?: string;
}

export function Badge({ tone, children, leading, className = "" }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider whitespace-nowrap uppercase ring-1 ring-inset ${TONE_CLASSES[tone]} ${className}`}
    >
      {leading}
      {children}
    </span>
  );
}
