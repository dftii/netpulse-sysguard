/** Segmented control that switches between the live backend and the in-browser demo engine. */

import { FlaskConical, Info, LoaderCircle, Server, TriangleAlert, type LucideIcon } from "lucide-react";
import { getApiBaseUrl } from "../../services/modeResolver";
import type { ConnectionMode, TelemetryController } from "../../types/dashboard";
import { MODE_LABELS } from "./ConnectionStatus";

const OPTIONS: ReadonlyArray<{ mode: ConnectionMode; icon: LucideIcon }> = [
  { mode: "backend", icon: Server },
  { mode: "simulation", icon: FlaskConical },
];

export interface ModeSelectorProps {
  controller: TelemetryController;
}

export function ModeSelector({ controller }: ModeSelectorProps) {
  const { mode, resolving, autoSelected, backendAvailable, setMode } = controller;

  return (
    <div className="flex flex-col items-start gap-2 lg:items-end">
      <div className="flex items-center gap-3">
        {resolving ? (
          <span className="flex items-center gap-1.5 font-mono text-[11px] text-slate-400" role="status">
            <LoaderCircle className="size-3.5 animate-spin text-noc-accent" aria-hidden="true" />
            Probing backend…
          </span>
        ) : null}
        <div
          role="group"
          aria-label="Telemetry source"
          className="inline-flex rounded-lg border border-noc-border bg-black/40 p-0.5"
        >
          {OPTIONS.map(({ mode: optionMode, icon: Icon }) => {
            // While the initial probe runs `mode` is only a placeholder, so no option is shown as active.
            const active = !resolving && mode === optionMode;
            return (
              <button
                key={optionMode}
                type="button"
                aria-pressed={active}
                disabled={resolving}
                onClick={() => {
                  if (!active) setMode(optionMode);
                }}
                className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-medium transition focus-visible:ring-2 focus-visible:ring-noc-accent/70 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50 ${
                  active
                    ? "bg-noc-accent/15 text-cyan-200 shadow-[inset_0_0_0_1px_rgb(34_211_238/0.4)]"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Icon className="size-3.5" aria-hidden="true" />
                {MODE_LABELS[optionMode]}
              </button>
            );
          })}
        </div>
      </div>

      {autoSelected || backendAvailable === false ? (
        <div className="flex flex-col gap-1 lg:items-end" aria-live="polite">
          {/* A null probe result means the backend was never probed: static hosting or a forced demo build. */}
          {autoSelected && backendAvailable === null ? (
            <p className="flex items-center gap-1.5 text-[11px] text-sky-300/90">
              <Info className="size-3.5 shrink-0" aria-hidden="true" />
              Static hosting detected — running the in-browser engine
            </p>
          ) : null}
          {backendAvailable === false ? (
            <p className="flex items-center gap-1.5 text-[11px] text-amber-300/90">
              <TriangleAlert className="size-3.5 shrink-0" aria-hidden="true" />
              <span className="min-w-0 break-all">Backend unreachable at {getApiBaseUrl()}
                {mode === "simulation" ? " — running the in-browser engine" : ""}
              </span>
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
