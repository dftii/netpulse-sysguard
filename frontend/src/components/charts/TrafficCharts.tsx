/**
 * Two live panels for the focused scope (whole cluster or one selected node):
 * "Network traffic" in Mbps and "CPU load" in percent, over a 120 s rolling window.
 */

import { Cpu, Network } from "lucide-react";
import { useMemo, type ReactNode } from "react";
import { formatBandwidth, formatPercent } from "../../lib/format";
import { LEVEL_STYLES, THRESHOLDS, loadLevel } from "../../lib/thresholds";
import { HISTORY_LENGTH, type ClusterHistoryPoint, type NodeHistoryPoint } from "../../types/dashboard";
import type { NodeTelemetry } from "../../types/api";
import { Panel } from "../ui/Panel";
import { TimeSeriesChart, type ChartSeries } from "./TimeSeriesChart";

export interface TrafficChartsProps {
  clusterHistory: ClusterHistoryPoint[];
  nodeHistory: Record<number, NodeHistoryPoint[]>;
  nodes: NodeTelemetry[];
  selectedNodeId: number | null;
}

const COLORS = {
  download: "#22d3ee",
  upload: "#a78bfa",
  cpu: "#60a5fa",
  memory: "#f472b6",
} as const;

const CHART_HEIGHT = 190;

function lastOf(values: readonly (number | null)[]): number | null {
  const last = values[values.length - 1];
  return last === undefined ? null : last;
}

function formatMbps(mbps: number | null): string {
  return mbps === null ? "—" : formatBandwidth(mbps * 1000);
}

function ScopeChip({ label }: { label: string }) {
  return (
    <span className="max-w-40 truncate rounded border border-noc-accent/30 bg-noc-accent/10 px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider text-cyan-200 uppercase">
      {label}
    </span>
  );
}

function LegendItem({ color, label, value }: { color: string; label: string; value: string }) {
  return (
    <li className="flex items-center gap-2 text-[11px]">
      <span className="size-2 rounded-full" style={{ backgroundColor: color }} aria-hidden="true" />
      <span className="text-slate-400">{label}</span>
      <span className="font-mono text-slate-200 tabular-nums">{value}</span>
    </li>
  );
}

interface HeadlineProps {
  value: ReactNode;
  valueClassName?: string;
  caption: ReactNode;
  legend: ReactNode;
}

function Headline({ value, valueClassName = "text-slate-100", caption, legend }: HeadlineProps) {
  return (
    <div className="mb-3 flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
      <div className="min-w-0">
        <div className={`font-mono text-2xl leading-none font-semibold tabular-nums ${valueClassName}`}>{value}</div>
        <div className="mt-1.5 truncate text-[11px] text-slate-500">{caption}</div>
      </div>
      <ul className="flex flex-wrap items-center gap-x-4 gap-y-1">{legend}</ul>
    </div>
  );
}

export function TrafficCharts({ clusterHistory, nodeHistory, nodes, selectedNodeId }: TrafficChartsProps) {
  const selectedNode = useMemo(
    () => (selectedNodeId === null ? null : (nodes.find((n) => n.node_id === selectedNodeId) ?? null)),
    [nodes, selectedNodeId],
  );

  const data = useMemo(() => {
    if (selectedNode) {
      const points = (nodeHistory[selectedNode.node_id] ?? []).slice(-HISTORY_LENGTH);
      const timestamps = points.map((p) => p.t);
      const traffic: ChartSeries[] = [
        { key: "net", label: "Traffic", color: COLORS.download, values: points.map((p) => p.netMbps) },
      ];
      const load: ChartSeries[] = [
        { key: "cpu", label: "CPU", color: COLORS.cpu, values: points.map((p) => p.cpu) },
        { key: "memory", label: "Memory", color: COLORS.memory, values: points.map((p) => p.memory) },
      ];
      return { timestamps, traffic, load };
    }
    const points = clusterHistory.slice(-HISTORY_LENGTH);
    const timestamps = points.map((p) => p.t);
    const traffic: ChartSeries[] = [
      { key: "down", label: "Download", color: COLORS.download, values: points.map((p) => p.downloadMbps) },
      { key: "up", label: "Upload", color: COLORS.upload, values: points.map((p) => p.uploadMbps) },
    ];
    const load: ChartSeries[] = [
      { key: "avg-cpu", label: "Avg CPU", color: COLORS.cpu, values: points.map((p) => p.avgCpu) },
    ];
    return { timestamps, traffic, load };
  }, [selectedNode, nodeHistory, clusterHistory]);

  const scope = selectedNode ? selectedNode.display_name : "Cluster";
  const scopeChip = <ScopeChip label={scope} />;

  const trafficLatest = data.traffic.map((s) => lastOf(s.values));
  const loadLatest = data.load.map((s) => lastOf(s.values));

  // Network headline
  let trafficTotal: number | null;
  let trafficCaption: ReactNode;
  if (selectedNode) {
    trafficTotal = trafficLatest[0] ?? null;
    const capacity = selectedNode.link_capacity_mbps;
    const utilisation = trafficTotal !== null && capacity > 0 ? (trafficTotal / capacity) * 100 : null;
    trafficCaption =
      utilisation === null
        ? "Upload + download"
        : `${formatPercent(utilisation)} of ${capacity.toLocaleString("en-US")} Mbps link`;
  } else {
    const down = trafficLatest[0] ?? null;
    const up = trafficLatest[1] ?? null;
    trafficTotal = down !== null && up !== null ? down + up : null;
    trafficCaption = "Aggregate upload + download";
  }

  // CPU headline
  const cpuNow = loadLatest[0] ?? null;
  const cpuLevel = loadLevel(cpuNow, THRESHOLDS.cpu);

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Panel
        title="Network traffic"
        icon={<Network className="size-4 text-noc-accent" aria-hidden="true" />}
        actions={scopeChip}
      >
        <Headline
          value={formatMbps(trafficTotal)}
          caption={trafficCaption}
          legend={data.traffic.map((s, i) => (
            <LegendItem key={s.key} color={s.color} label={s.label} value={formatMbps(trafficLatest[i] ?? null)} />
          ))}
        />
        <TimeSeriesChart
          series={data.traffic}
          timestamps={data.timestamps}
          unit="Mbps"
          height={CHART_HEIGHT}
          windowSeconds={HISTORY_LENGTH}
          title={`Network traffic, ${scope}`}
        />
      </Panel>

      <Panel
        title="CPU load"
        icon={<Cpu className="size-4 text-noc-accent" aria-hidden="true" />}
        actions={scopeChip}
      >
        <Headline
          value={cpuNow === null ? "—" : formatPercent(cpuNow)}
          valueClassName={LEVEL_STYLES[cpuLevel].text}
          caption={selectedNode ? `${selectedNode.hostname} processor utilisation` : "Mean across all nodes"}
          legend={data.load.map((s, i) => (
            <LegendItem
              key={s.key}
              color={s.color}
              label={s.label}
              value={loadLatest[i] === null || loadLatest[i] === undefined ? "—" : formatPercent(loadLatest[i]!)}
            />
          ))}
        />
        <TimeSeriesChart
          series={data.load}
          timestamps={data.timestamps}
          yMax={100}
          unit="%"
          height={CHART_HEIGHT}
          windowSeconds={HISTORY_LENGTH}
          title={`CPU load, ${scope}`}
          formatValue={(v) => v.toFixed(1)}
        />
      </Panel>
    </div>
  );
}
