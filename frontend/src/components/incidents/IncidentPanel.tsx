import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CheckCheck, Siren } from "lucide-react";
import type { TelemetryController } from "../../types/dashboard";
import { IncidentRow } from "./IncidentRow";
import { InjectIncidentForm } from "./InjectIncidentForm";

interface IncidentPanelProps {
  controller: TelemetryController;
}

type IncidentFilter = "all" | "critical" | "warning" | "unacknowledged";

const FILTERS: ReadonlyArray<{ id: IncidentFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "warning", label: "Warning" },
  { id: "unacknowledged", label: "Unacknowledged" },
];

const FLASH_MS = 3000;
const FRESH_ALERT_MS = 15_000;
const CLOCK_TICK_MS = 5000;
const PAGE_SIZE = 50;

export function IncidentPanel({ controller }: IncidentPanelProps) {
  const alerts = controller.state.alerts;
  const [filter, setFilter] = useState<IncidentFilter>("all");
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [flashing, setFlashing] = useState<ReadonlySet<number>>(() => new Set());
  const [nowMs, setNowMs] = useState(() => Date.now());

  const seenIds = useRef<Set<number> | null>(null);
  const flashTimers = useRef<Set<number>>(new Set());
  const acknowledgeRef = useRef(controller.acknowledgeAlert);
  useEffect(() => {
    acknowledgeRef.current = controller.acknowledgeAlert;
  });

  const onAcknowledge = useCallback((alertId: number) => acknowledgeRef.current(alertId), []);

  // Relative timestamps refresh on a slow clock.
  useEffect(() => {
    const interval = window.setInterval(() => setNowMs(Date.now()), CLOCK_TICK_MS);
    return () => window.clearInterval(interval);
  }, []);

  // Highlight alerts that arrive after the panel is mounted; the first batch is not "new".
  useEffect(() => {
    if (seenIds.current === null) {
      seenIds.current = new Set(alerts.map((alert) => alert.id));
      return;
    }
    const seen = seenIds.current;
    const unseen = alerts.filter((alert) => !seen.has(alert.id));
    for (const alert of unseen) seen.add(alert.id);
    // History loaded after mount (initial listAlerts, reconnect reloads) is unseen but not new:
    // only alerts detected moments ago deserve the highlight.
    const freshSince = Date.now() - FRESH_ALERT_MS;
    const arrived = unseen.filter((alert) => Date.parse(alert.detected_at) >= freshSince).map((alert) => alert.id);
    if (arrived.length === 0) return;

    setFlashing((previous) => new Set([...previous, ...arrived]));
    const timer = window.setTimeout(() => {
      flashTimers.current.delete(timer);
      setFlashing((previous) => {
        const next = new Set(previous);
        for (const id of arrived) next.delete(id);
        return next;
      });
    }, FLASH_MS);
    flashTimers.current.add(timer);
  }, [alerts]);

  useEffect(() => {
    const timers = flashTimers.current;
    return () => {
      for (const timer of timers) window.clearTimeout(timer);
      timers.clear();
    };
  }, []);

  const counts = useMemo(() => {
    let critical = 0;
    let warning = 0;
    let unacknowledged = 0;
    for (const alert of alerts) {
      if (alert.severity === "critical") critical += 1;
      if (alert.severity === "warning") warning += 1;
      if (!alert.acknowledged) unacknowledged += 1;
    }
    return { all: alerts.length, critical, warning, unacknowledged };
  }, [alerts]);

  const filtered = useMemo(() => {
    switch (filter) {
      case "critical":
        return alerts.filter((alert) => alert.severity === "critical");
      case "warning":
        return alerts.filter((alert) => alert.severity === "warning");
      case "unacknowledged":
        return alerts.filter((alert) => !alert.acknowledged);
      default:
        return alerts;
    }
  }, [alerts, filter]);

  const visible = filtered.slice(0, visibleCount);

  return (
    <section className="noc-panel" aria-labelledby="incident-panel-title">
      <header className="noc-panel-header">
        <h2 id="incident-panel-title" className="noc-title">
          <Siren className="size-4 text-rose-400" aria-hidden="true" />
          Incidents
        </h2>
        <dl className="flex items-center gap-3 font-mono text-[11px]" aria-label="Incident counts">
          <div className="flex items-center gap-1">
            <dt className="text-slate-500">crit</dt>
            <dd className={`tabular-nums ${counts.critical > 0 ? "font-semibold text-rose-300" : "text-slate-400"}`}>{counts.critical}</dd>
          </div>
          <div className="flex items-center gap-1">
            <dt className="text-slate-500">warn</dt>
            <dd className={`tabular-nums ${counts.warning > 0 ? "font-semibold text-amber-300" : "text-slate-400"}`}>{counts.warning}</dd>
          </div>
          <div className="flex items-center gap-1">
            <dt className="text-slate-500">unack</dt>
            <dd className={`tabular-nums ${counts.unacknowledged > 0 ? "font-semibold text-noc-accent" : "text-slate-400"}`}>
              {counts.unacknowledged}
            </dd>
          </div>
        </dl>
      </header>

      <div className="space-y-3 p-4">
        <InjectIncidentForm controller={controller} />

        <div role="group" aria-label="Filter incidents" className="flex flex-wrap gap-1.5">
          {FILTERS.map((entry) => {
            const active = entry.id === filter;
            return (
              <button
                key={entry.id}
                type="button"
                aria-pressed={active}
                onClick={() => {
                  setFilter(entry.id);
                  setVisibleCount(PAGE_SIZE);
                }}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] transition focus-visible:ring-2 focus-visible:ring-noc-accent/60 focus-visible:outline-none ${
                  active
                    ? "border-noc-accent/60 bg-noc-accent/10 text-cyan-200"
                    : "border-noc-border bg-black/30 text-slate-400 hover:border-slate-600 hover:text-slate-200"
                }`}
              >
                {entry.label}
                <span className="font-mono tabular-nums text-slate-500">{counts[entry.id]}</span>
              </button>
            );
          })}
        </div>

        {visible.length === 0 ? (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-noc-border py-8 text-center">
            <CheckCheck className="size-6 text-emerald-400" aria-hidden="true" />
            <p className="text-xs text-slate-400">
              {alerts.length === 0 ? "No incidents detected. All monitored nodes are within baseline." : "No incidents match this filter."}
            </p>
          </div>
        ) : (
          <>
            <ul className="max-h-[34rem] space-y-2 overflow-y-auto pr-1" aria-label="Incident list">
              {visible.map((alert) => (
                <IncidentRow
                  key={alert.id}
                  alert={alert}
                  flashing={flashing.has(alert.id)}
                  nowMs={nowMs}
                  onAcknowledge={onAcknowledge}
                />
              ))}
            </ul>
            <div className="flex items-center justify-between font-mono text-[11px] text-slate-500">
              <span>
                Showing {visible.length} of {filtered.length}
              </span>
              {visible.length < filtered.length && (
                <button type="button" className="noc-button" onClick={() => setVisibleCount((count) => count + PAGE_SIZE)}>
                  Show more
                </button>
              )}
            </div>
          </>
        )}
      </div>
    </section>
  );
}
