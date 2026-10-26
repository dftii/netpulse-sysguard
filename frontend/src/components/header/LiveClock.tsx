/** Ticking UTC and local wall clock. */

import { Clock } from "lucide-react";
import { useNow } from "./useNow";

const UTC_TIME = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
  timeZone: "UTC",
});

const LOCAL_TIME = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
  timeZoneName: "short",
});

const UTC_DATE = new Intl.DateTimeFormat("en-CA", { year: "numeric", month: "2-digit", day: "2-digit", timeZone: "UTC" });

function splitLocal(date: Date): { time: string; zone: string } {
  const parts = LOCAL_TIME.formatToParts(date);
  const time = parts
    .filter((p) => p.type === "hour" || p.type === "minute" || p.type === "second" || p.type === "literal")
    .map((p) => p.value)
    .join("")
    .trim();
  const zone = parts.find((p) => p.type === "timeZoneName")?.value ?? "";
  return { time, zone };
}

export function LiveClock() {
  const now = useNow(1000);
  const date = new Date(now);
  const local = splitLocal(date);

  return (
    <div className="flex items-center gap-3" role="timer" aria-label="Current time">
      <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-slate-800/60 text-slate-400 ring-1 ring-inset ring-slate-700/60">
        <Clock className="size-4" aria-hidden="true" />
      </span>
      <div className="font-mono leading-tight">
        <div className="text-sm font-semibold text-slate-100 tabular-nums">
          {UTC_TIME.format(date)} <span className="text-[10px] font-medium tracking-widest text-noc-accent">UTC</span>
          <span className="ml-2 text-[10px] font-normal text-slate-500">{UTC_DATE.format(date)}</span>
        </div>
        <div className="text-[11px] text-slate-500 tabular-nums">
          {local.time} <span className="text-[10px] tracking-widest">{local.zone || "LOCAL"}</span>
        </div>
      </div>
    </div>
  );
}
