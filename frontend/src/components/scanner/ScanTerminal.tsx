import { memo, useEffect, useRef } from "react";
import { formatElapsed } from "./scanFormat";
import type { TermLine } from "./scanScript";

export type ScanPhase = "idle" | "running" | "revealing" | "done" | "error";

interface ScanTerminalProps {
  lines: TermLine[];
  phase: ScanPhase;
  /** 0-100. */
  progress: number;
  elapsedMs: number;
}

const TerminalLine = memo(function TerminalLine({ line }: { line: TermLine }) {
  return (
    <div className="break-words whitespace-pre-wrap">
      {line.segments.map((segment, index) => (
        <span key={index} className={segment.className}>
          {segment.text}
        </span>
      ))}
    </div>
  );
});

/** Scrolling nmap-style output with a blinking cursor and a progress bar while an audit is in flight. */
export function ScanTerminal({ lines, phase, progress, elapsedMs }: ScanTerminalProps) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const busy = phase === "running" || phase === "revealing";

  useEffect(() => {
    const viewport = viewportRef.current;
    if (viewport !== null) viewport.scrollTop = viewport.scrollHeight;
  }, [lines.length]);

  const rounded = Math.round(progress);

  return (
    <div className="noc-terminal overflow-hidden">
      <div className="flex items-center justify-between gap-3 border-b border-noc-border bg-noc-panel-2/80 px-3 py-1.5">
        <div className="flex items-center gap-1.5" aria-hidden="true">
          <span className="size-2.5 rounded-full bg-rose-500/80" />
          <span className="size-2.5 rounded-full bg-amber-400/80" />
          <span className="size-2.5 rounded-full bg-emerald-400/80" />
        </div>
        <span className="truncate text-[11px] text-slate-500">netpulse-audit: tcp-connect</span>
        <span className="w-12 text-right text-[11px] text-slate-500 tabular-nums">{busy ? formatElapsed(elapsedMs) : ""}</span>
      </div>

      <div
        ref={viewportRef}
        role="log"
        aria-label="Port scan output"
        aria-live="off"
        tabIndex={0}
        className="h-72 overflow-y-auto px-3 py-2 focus-visible:ring-1 focus-visible:ring-noc-accent/50 focus-visible:outline-none"
      >
        {lines.length === 0 && phase === "idle" && (
          <div className="text-slate-500">Ready. Choose a target and a port profile, then press Launch scan.</div>
        )}
        {lines.map((line) => (
          <TerminalLine key={line.id} line={line} />
        ))}
        <div className="text-emerald-300">
          <span className="text-noc-accent">netpulse@noc</span>
          <span className="text-slate-500">:</span>
          <span className="text-sky-300">~</span>
          <span className="text-slate-500">$ </span>
          <span className="animate-blink text-slate-200">{busy ? "_" : "█"}</span>
        </div>
      </div>

      {busy && (
        <div className="border-t border-noc-border px-3 py-2">
          <div className="mb-1 flex items-center justify-between text-[11px] text-slate-500">
            <span>{phase === "running" ? "Probing ports ..." : "Receiving results ..."}</span>
            <span className="tabular-nums">{rounded}%</span>
          </div>
          <div
            role="progressbar"
            aria-label="Scan progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={rounded}
            className="h-1.5 overflow-hidden rounded-full bg-noc-grid"
          >
            <div
              className="h-full rounded-full bg-noc-accent shadow-[0_0_8px_rgb(34_211_238/0.7)] transition-[width] duration-200 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
}
