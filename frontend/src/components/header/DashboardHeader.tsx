/** Top of the dashboard: brand, cluster status, clock, connection state, source selector and KPIs. */

import { Radar } from "lucide-react";
import type { TelemetryController } from "../../types/dashboard";
import { ClusterStatusPill } from "./ClusterStatusPill";
import { ConnectionStatus } from "./ConnectionStatus";
import { ExportReportButton } from "./ExportReportButton";
import { KpiRow } from "./KpiRow";
import { LiveClock } from "./LiveClock";
import { ModeSelector } from "./ModeSelector";

export interface DashboardHeaderProps {
  controller: TelemetryController;
}

export function DashboardHeader({ controller }: DashboardHeaderProps) {
  const { state } = controller;

  return (
    <header className="flex flex-col gap-4">
      <div className="noc-panel flex flex-col">
        <div className="flex flex-col gap-4 p-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-noc-accent/10 text-noc-accent shadow-[0_0_24px_-8px_rgb(34_211_238/0.7)] ring-1 ring-inset ring-noc-accent/40">
              <Radar className="size-6" aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <h1 className="truncate text-lg leading-tight font-semibold tracking-tight text-white">NetPulse SysGuard</h1>
              <p className="text-[11px] tracking-[0.2em] text-noc-muted uppercase">Network Operations Center</p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
            <ClusterStatusPill summary={state.frame?.summary ?? null} phase={state.status.phase} />
            <LiveClock />
            <ExportReportButton controller={controller} />
          </div>
        </div>

        <div className="flex flex-col gap-3 border-t border-noc-border px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
          <ConnectionStatus status={state.status} />
          <ModeSelector controller={controller} />
        </div>
      </div>

      <KpiRow state={state} />
    </header>
  );
}
