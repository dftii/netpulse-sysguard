import { useCallback, useLayoutEffect, useMemo, useRef, useState } from "react";
import { ArrowDownToLine, Eraser, Pause, Play, Search } from "lucide-react";
import type { LogEntry, LogLevel } from "../../types/dashboard";
import { LEVEL_CHIP, LOG_LEVELS, LogRow, searchableText } from "./LogRow";

interface LogConsoleProps {
  logs: LogEntry[];
  onClear: () => void;
}

interface PauseState {
  snapshot: LogEntry[];
  /** Highest log id present when the view was frozen. */
  lastId: number;
}

const MAX_RENDERED_LINES = 400;
const BOTTOM_TOLERANCE_PX = 24;

function lastIdOf(entries: readonly LogEntry[]): number {
  return entries[entries.length - 1]?.id ?? 0;
}

export function LogConsole({ logs, onClear }: LogConsoleProps) {
  const [pause, setPause] = useState<PauseState | null>(null);
  const [enabledLevels, setEnabledLevels] = useState<ReadonlySet<LogLevel>>(() => new Set(LOG_LEVELS));
  const [search, setSearch] = useState("");
  const [atBottom, setAtBottom] = useState(true);

  const viewportRef = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);

  const source = pause === null ? logs : pause.snapshot;
  const pendingCount = pause === null ? 0 : logs.filter((entry) => entry.id > pause.lastId).length;

  const levelCounts = useMemo(() => {
    const counts: Record<LogLevel, number> = { debug: 0, info: 0, warn: 0, error: 0, critical: 0 };
    for (const entry of source) counts[entry.level] += 1;
    return counts;
  }, [source]);

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const matches = source.filter(
      (entry) => enabledLevels.has(entry.level) && (needle === "" || searchableText(entry).includes(needle)),
    );
    return matches.length > MAX_RENDERED_LINES ? matches.slice(-MAX_RENDERED_LINES) : matches;
  }, [source, enabledLevels, search]);

  const newestVisibleId = lastIdOf(visible);

  // Keep the view pinned to the newest line unless the operator scrolled up.
  useLayoutEffect(() => {
    const viewport = viewportRef.current;
    if (viewport !== null && stickToBottom.current) viewport.scrollTop = viewport.scrollHeight;
  }, [newestVisibleId, visible.length]);

  const handleScroll = useCallback(() => {
    const viewport = viewportRef.current;
    if (viewport === null) return;
    const distance = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight;
    const nearBottom = distance <= BOTTOM_TOLERANCE_PX;
    stickToBottom.current = nearBottom;
    setAtBottom(nearBottom);
  }, []);

  const jumpToLatest = () => {
    const viewport = viewportRef.current;
    if (viewport === null) return;
    stickToBottom.current = true;
    viewport.scrollTo({ top: viewport.scrollHeight });
    setAtBottom(true);
  };

  const togglePause = () => {
    setPause((current) => (current === null ? { snapshot: logs, lastId: lastIdOf(logs) } : null));
  };

  const toggleLevel = (level: LogLevel) => {
    setEnabledLevels((current) => {
      const next = new Set(current);
      if (next.has(level)) next.delete(level);
      else next.add(level);
      return next;
    });
  };

  const handleClear = () => {
    onClear();
    setPause((current) => (current === null ? null : { snapshot: [], lastId: lastIdOf(logs) }));
  };

  const paused = pause !== null;

  return (
    <section className="noc-panel overflow-hidden" aria-labelledby="log-console-title">
      <div className="flex items-center gap-3 border-b border-noc-border bg-noc-panel-2/80 px-3 py-2">
        <div className="flex shrink-0 items-center gap-1.5" aria-hidden="true">
          <span className="size-2.5 rounded-full bg-rose-500/80" />
          <span className="size-2.5 rounded-full bg-amber-400/80" />
          <span className="size-2.5 rounded-full bg-emerald-400/80" />
        </div>
        <h2 id="log-console-title" className="min-w-0 flex-1 truncate font-mono text-[11px] text-slate-400">
          netpulse@noc:~$ journalctl -f -u sysguard
        </h2>
        {paused && (
          <span className="shrink-0 rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider text-amber-300 uppercase ring-1 ring-amber-500/30 ring-inset">
            Paused{pendingCount > 0 ? ` +${pendingCount}` : ""}
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 border-b border-noc-border px-3 py-2">
        <div className="relative min-w-0 flex-1 basis-40">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-slate-500" aria-hidden="true" />
          <label htmlFor="log-search" className="sr-only">
            Filter log lines
          </label>
          <input
            id="log-search"
            type="search"
            className="noc-input w-full pl-8"
            placeholder="grep host, source or text"
            autoComplete="off"
            spellCheck={false}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>

        <button type="button" className="noc-button" onClick={togglePause} aria-pressed={paused}>
          {paused ? <Play className="size-3.5" aria-hidden="true" /> : <Pause className="size-3.5" aria-hidden="true" />}
          {paused ? "Resume" : "Pause"}
        </button>
        <button type="button" className="noc-button" onClick={handleClear} disabled={logs.length === 0 && source.length === 0}>
          <Eraser className="size-3.5" aria-hidden="true" />
          Clear
        </button>
      </div>

      <div role="group" aria-label="Filter by log level" className="flex flex-wrap gap-1.5 border-b border-noc-border px-3 py-2">
        {LOG_LEVELS.map((level) => {
          const active = enabledLevels.has(level);
          return (
            <button
              key={level}
              type="button"
              aria-pressed={active}
              onClick={() => toggleLevel(level)}
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[11px] uppercase transition focus-visible:ring-2 focus-visible:ring-noc-accent/60 focus-visible:outline-none ${
                active ? LEVEL_CHIP[level] : "border-noc-border bg-black/30 text-slate-600 line-through"
              }`}
            >
              {level === "critical" ? "crit" : level}
              <span className="tabular-nums opacity-70">{levelCounts[level]}</span>
            </button>
          );
        })}
      </div>

      <div className="relative">
        <div
          ref={viewportRef}
          onScroll={handleScroll}
          role="log"
          aria-label="System log"
          aria-live="off"
          tabIndex={0}
          className="noc-terminal h-80 overflow-y-auto rounded-none border-0 px-3 py-2 focus-visible:ring-1 focus-visible:ring-noc-accent/50 focus-visible:outline-none"
        >
          {visible.length === 0 && (
            <div className="text-slate-500">
              {source.length === 0 ? "-- No entries --" : "-- No entries match the current filters --"}
            </div>
          )}
          {visible.map((entry) => (
            <LogRow key={entry.id} entry={entry} />
          ))}
          <div>
            <span className="text-noc-accent">netpulse@noc</span>
            <span className="text-slate-500">:</span>
            <span className="text-sky-300">~</span>
            <span className="text-slate-500">$ </span>
            <span className="animate-blink text-slate-200">█</span>
          </div>
        </div>

        {!atBottom && (
          <button
            type="button"
            onClick={jumpToLatest}
            className="noc-button noc-button-primary absolute right-3 bottom-3 shadow-lg shadow-black/60"
          >
            <ArrowDownToLine className="size-3.5" aria-hidden="true" />
            Jump to latest
            {pendingCount > 0 && <span className="font-mono text-amber-300">+{pendingCount}</span>}
          </button>
        )}
      </div>

      <div className="flex items-center justify-between gap-3 border-t border-noc-border px-3 py-1.5 font-mono text-[11px] text-slate-500">
        <span>
          {visible.length} / {source.length} lines
        </span>
        <span>{paused ? `view frozen, ${pendingCount} new` : "following"}</span>
      </div>
    </section>
  );
}
