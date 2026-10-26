import { Code, LoaderCircle } from "lucide-react";
import { useCallback, useMemo, useState } from "react";

import { TrafficCharts } from "./components/charts/TrafficCharts";
import { LogConsole } from "./components/console/LogConsole";
import { DashboardHeader } from "./components/header/DashboardHeader";
import { IncidentPanel } from "./components/incidents/IncidentPanel";
import { PortScanConsole } from "./components/scanner/PortScanConsole";
import { ServerGrid } from "./components/servers/ServerGrid";
import { useTelemetry } from "./hooks/useTelemetry";
import type { NodeTelemetry } from "./types/api";

const REPOSITORY_URL = "https://github.com/dftii/netpulse-sysguard";
const NO_NODES: NodeTelemetry[] = [];

/** NetPulse SysGuard network operations center: one screen, every panel fed by useTelemetry. */
export default function App() {
  const controller = useTelemetry();
  const { state } = controller;
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null);

  const nodes = state.frame?.nodes ?? NO_NODES;
  // Drop a selection that no longer exists (e.g. after switching between backend and simulation).
  const effectiveSelection = useMemo(
    () => (selectedNodeId !== null && nodes.some((node) => node.node_id === selectedNodeId) ? selectedNodeId : null),
    [nodes, selectedNodeId],
  );
  const handleSelect = useCallback((nodeId: number | null) => setSelectedNodeId(nodeId), []);
  const { clearLogs } = controller;

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-[1800px] flex-col gap-4 px-4 py-4 sm:px-6 lg:py-6">
      <DashboardHeader controller={controller} />

      <main className="flex flex-col gap-4">
        {state.frame === null ? (
          <section className="noc-panel flex min-h-64 flex-col items-center justify-center gap-3 p-8 text-center">
            <LoaderCircle className="size-6 animate-spin text-noc-accent" aria-hidden="true" />
            <p className="font-mono text-xs tracking-wide text-slate-400">
              {controller.resolving ? "Probing backend and preparing telemetry source…" : "Waiting for the first telemetry frame…"}
            </p>
            <p className="max-w-md text-xs text-slate-500">{state.status.detail}</p>
          </section>
        ) : (
          <>
            <ServerGrid
              nodes={nodes}
              history={state.nodeHistory}
              selectedNodeId={effectiveSelection}
              onSelect={handleSelect}
            />
            <TrafficCharts
              clusterHistory={state.clusterHistory}
              nodeHistory={state.nodeHistory}
              nodes={nodes}
              selectedNodeId={effectiveSelection}
            />
          </>
        )}

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <PortScanConsole controller={controller} nodes={nodes} preselectedNodeId={effectiveSelection} />
          <IncidentPanel controller={controller} />
        </div>

        <LogConsole logs={state.logs} onClear={clearLogs} />
      </main>

      <footer className="flex flex-col items-center justify-between gap-2 border-t border-noc-border pt-4 pb-2 text-[11px] text-slate-500 sm:flex-row">
        <span className="font-mono">
          NetPulse SysGuard · {controller.mode === "backend" ? "live backend telemetry" : "in-browser simulation engine"}
        </span>
        <a
          href={REPOSITORY_URL}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1.5 transition hover:text-noc-accent"
        >
          <Code className="size-3.5" aria-hidden="true" />
          dftii/netpulse-sysguard
        </a>
      </footer>
    </div>
  );
}
