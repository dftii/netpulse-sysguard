import { memo } from "react";
import type { LogEntry, LogLevel } from "../../types/dashboard";

export const LOG_LEVELS: readonly LogLevel[] = ["debug", "info", "warn", "error", "critical"];

export const LEVEL_LABEL: Record<LogLevel, string> = {
  debug: "DEBUG",
  info: "INFO ",
  warn: "WARN ",
  error: "ERROR",
  critical: "CRIT ",
};

/** Text colour of the level tag and of the message body. */
export const LEVEL_TONE: Record<LogLevel, { tag: string; message: string }> = {
  debug: { tag: "text-slate-500", message: "text-slate-500" },
  info: { tag: "text-sky-300", message: "text-slate-300" },
  warn: { tag: "text-amber-300", message: "text-amber-100" },
  error: { tag: "text-rose-400", message: "text-rose-200" },
  critical: { tag: "bg-rose-500/20 font-bold text-rose-300", message: "font-semibold text-rose-200" },
};

/** Chip colours when the level filter is active. */
export const LEVEL_CHIP: Record<LogLevel, string> = {
  debug: "border-slate-500/50 bg-slate-500/10 text-slate-300",
  info: "border-sky-500/50 bg-sky-500/10 text-sky-300",
  warn: "border-amber-500/50 bg-amber-500/10 text-amber-300",
  error: "border-rose-500/50 bg-rose-500/10 text-rose-300",
  critical: "border-rose-500/70 bg-rose-500/20 text-rose-200",
};

const HOST_COLOURS = [
  "text-cyan-300",
  "text-violet-300",
  "text-emerald-300",
  "text-fuchsia-300",
  "text-lime-300",
  "text-orange-300",
  "text-teal-300",
  "text-indigo-300",
] as const;

function hostColour(host: string): string {
  let hash = 0;
  for (let index = 0; index < host.length; index += 1) {
    hash = (hash * 31 + host.charCodeAt(index)) >>> 0;
  }
  return HOST_COLOURS[hash % HOST_COLOURS.length] ?? HOST_COLOURS[0];
}

const SYSLOG_FALLBACK_HOST = "noc-core";

/** "Oct 26 14:03:27", exactly like a journald/syslog timestamp (day padded to two characters). */
export function formatSyslogTime(epochMs: number): string {
  const date = new Date(epochMs);
  const month = date.toLocaleDateString("en-US", { month: "short" });
  const day = date.getDate().toString().padStart(2, " ");
  const clock = date.toLocaleTimeString("en-GB", { hour12: false });
  return `${month} ${day} ${clock}`;
}

/** Plain-text rendering of an entry, used by the search filter. */
export function searchableText(entry: LogEntry): string {
  return `${entry.host ?? SYSLOG_FALLBACK_HOST} ${entry.source} ${entry.level} ${entry.message}`.toLowerCase();
}

interface LogRowProps {
  entry: LogEntry;
}

export const LogRow = memo(function LogRow({ entry }: LogRowProps) {
  const host = entry.host ?? SYSLOG_FALLBACK_HOST;
  const tone = LEVEL_TONE[entry.level];
  return (
    <div className="break-words whitespace-pre-wrap">
      <span className="text-slate-500">{formatSyslogTime(entry.t)} </span>
      <span className={entry.host === null ? "text-slate-400" : hostColour(host)}>{host}</span>
      <span className="text-slate-500"> sysguard[{entry.source}]: </span>
      <span className={tone.tag}>{LEVEL_LABEL[entry.level]}</span>
      <span className={tone.message}> {entry.message}</span>
    </div>
  );
});
