/** One infrastructure node: identity, status, live gauges, CPU trend and network throughput. */

import {
  ArrowDown,
  ArrowUp,
  BrainCircuit,
  Database,
  Globe,
  HardDrive,
  KeyRound,
  Network,
  Server,
  Shield,
  TriangleAlert,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { memo, useMemo } from "react";
import {
  ANOMALY_LABELS,
  ROLE_LABELS,
  formatBandwidth,
  formatBytesMb,
  formatLatency,
  formatPercent,
  formatTemperature,
  formatUptime,
} from "../../lib/format";
import { LEVEL_STYLES, STATUS_STYLES, THRESHOLDS, loadLevel, type LoadLevel } from "../../lib/thresholds";
import type { NodeRole, NodeStatus, NodeTelemetry } from "../../types/api";
import type { NodeHistoryPoint } from "../../types/dashboard";
import { Sparkline } from "../charts/Sparkline";
import { Badge, type BadgeTone } from "../ui/Badge";
import { ProgressBar } from "../ui/ProgressBar";
import { StatusDot } from "../ui/StatusDot";

export const ROLE_ICONS: Record<NodeRole, LucideIcon> = {
  host: Server,
  database: Database,
  load_balancer: Network,
  ai_compute: BrainCircuit,
  firewall: Shield,
  web_server: Globe,
  cache: Zap,
  storage: HardDrive,
  domain_controller: KeyRound,
};

const TEMPERATURE_RANGE = { min: 20, max: 100 } as const;
const LATENCY_SCALE_MAX_MS = 300;
const SPARKLINE_POINTS = 60;

const STATUS_BADGE_TONE: Record<NodeStatus, BadgeTone> = {
  online: "ok",
  warning: "warn",
  critical: "crit",
  offline: "idle",
};

const STATUS_TILE: Record<NodeStatus, string> = {
  online: "bg-emerald-400/10 text-emerald-300 ring-emerald-400/25",
  warning: "bg-amber-400/10 text-amber-300 ring-amber-400/30",
  critical: "bg-rose-500/10 text-rose-300 ring-rose-500/40",
  offline: "bg-slate-500/10 text-slate-500 ring-slate-500/25",
};

const STATUS_FRAME: Record<NodeStatus, string> = {
  online: "border-noc-border hover:border-slate-600",
  warning: "border-amber-400/40 shadow-[0_0_24px_-10px_rgb(251_191_36/0.5)]",
  critical: "border-rose-500/60 shadow-[0_0_28px_-6px_rgb(244_63_94/0.6)]",
  offline: "border-dashed border-noc-border",
};

const LEVEL_HEX: Record<LoadLevel, string> = {
  ok: "#34d399",
  warn: "#fbbf24",
  crit: "#f43f5e",
  idle: "#475569",
};

function clamp01(value: number): number {
  return Math.min(1, Math.max(0, value));
}

function temperatureFraction(celsius: number): number {
  return clamp01((celsius - TEMPERATURE_RANGE.min) / (TEMPERATURE_RANGE.max - TEMPERATURE_RANGE.min));
}

/** Square-root scale: keeps healthy single-digit latencies visible while thresholds stay readable. */
function latencyFraction(ms: number): number {
  return Math.sqrt(clamp01(ms / LATENCY_SCALE_MAX_MS));
}

const CPU_MARKERS = [THRESHOLDS.cpu.warn / 100, THRESHOLDS.cpu.crit / 100] as const;
const MEMORY_MARKERS = [THRESHOLDS.memory.warn / 100, THRESHOLDS.memory.crit / 100] as const;
const DISK_MARKERS = [THRESHOLDS.disk.warn / 100, THRESHOLDS.disk.crit / 100] as const;
const TEMPERATURE_MARKERS = [
  temperatureFraction(THRESHOLDS.temperatureC.warn),
  temperatureFraction(THRESHOLDS.temperatureC.crit),
] as const;
const LATENCY_MARKERS = [latencyFraction(THRESHOLDS.latencyMs.warn), latencyFraction(THRESHOLDS.latencyMs.crit)] as const;

interface MetricRowProps {
  label: string;
  /** Accessible name of the gauge. */
  ariaLabel: string;
  valueText: string;
  detail?: string;
  fraction: number;
  level: LoadLevel;
  markers: readonly number[];
}

function MetricRow({ label, ariaLabel, valueText, detail, fraction, level, markers }: MetricRowProps) {
  return (
    <span className="block">
      <span className="mb-1 flex items-baseline justify-between gap-2 font-mono text-[10px] leading-none">
        <span className="font-semibold tracking-[0.14em] text-slate-500 uppercase">{label}</span>
        <span className="flex items-baseline gap-1.5">
          {detail ? <span className="text-slate-600">{detail}</span> : null}
          <span className={`text-[11px] font-semibold tabular-nums ${LEVEL_STYLES[level].text}`}>{valueText}</span>
        </span>
      </span>
      <ProgressBar fraction={fraction} level={level} ariaLabel={ariaLabel} valueText={valueText} markers={markers} />
    </span>
  );
}

export interface NodeCardProps {
  node: NodeTelemetry;
  /** Rolling history of this node, oldest first. */
  history: readonly NodeHistoryPoint[] | undefined;
  selected: boolean;
  /** Receives the node id to select it, or null to clear the selection. */
  onSelect: (nodeId: number | null) => void;
}

function NodeCardImpl({ node, history, selected, onSelect }: NodeCardProps) {
  const offline = node.status === "offline";
  const statusStyle = STATUS_STYLES[node.status];
  const RoleIcon = ROLE_ICONS[node.role];

  const cpuLevel = offline ? "idle" : loadLevel(node.cpu_percent, THRESHOLDS.cpu);
  const memoryLevel = offline ? "idle" : loadLevel(node.memory_percent, THRESHOLDS.memory);
  const diskLevel = offline ? "idle" : loadLevel(node.disk_percent, THRESHOLDS.disk);
  const temperature = offline ? null : node.temperature_c;
  const latency = offline ? null : node.latency_ms;
  const temperatureLevel = loadLevel(temperature, THRESHOLDS.temperatureC);
  const latencyLevel = loadLevel(latency, THRESHOLDS.latencyMs);

  const cpuText = offline ? "—" : formatPercent(node.cpu_percent);
  const memoryText = offline ? "—" : formatPercent(node.memory_percent);
  const diskText = offline ? "—" : formatPercent(node.disk_percent);
  const temperatureText = formatTemperature(temperature);
  const latencyText = formatLatency(latency);
  const memoryDetail = offline
    ? undefined
    : `${formatBytesMb(node.memory_used_mb)} / ${formatBytesMb(node.memory_total_mb)}`;

  const cpuSeries = useMemo(
    () => (offline || !history ? [] : history.slice(-SPARKLINE_POINTS).map((p) => p.cpu)),
    [history, offline],
  );

  const summary =
    `${node.display_name}, ${ROLE_LABELS[node.role]}, ${statusStyle.label.toLowerCase()}. ` +
    (offline
      ? "Host unreachable. "
      : `CPU ${cpuText}, memory ${memoryText}, storage ${diskText}, temperature ${temperatureText}, latency ${latencyText}. `) +
    (node.simulated_incident ? `Active incident: ${ANOMALY_LABELS[node.simulated_incident]}. ` : "") +
    (selected ? "Selected. Press to clear focus." : "Press to focus the charts on this node.");

  const ringClass = selected
    ? "ring-2 ring-noc-accent/70 shadow-[0_0_28px_-8px_rgb(34_211_238/0.45)]"
    : node.status === "critical" || node.status === "warning"
      ? `ring-1 ${statusStyle.ring}`
      : "";

  return (
    <button
      type="button"
      aria-pressed={selected}
      aria-label={summary}
      onClick={() => onSelect(selected ? null : node.node_id)}
      className={`noc-panel relative flex h-full w-full cursor-pointer flex-col gap-3.5 overflow-hidden p-3.5 text-left transition-[border-color,box-shadow] duration-300 focus-visible:ring-2 focus-visible:ring-noc-accent focus-visible:outline-none ${STATUS_FRAME[node.status]} ${ringClass}`}
    >
      {node.status === "critical" ? (
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 animate-pulse rounded-xl ring-1 ring-inset ring-rose-500/30"
        />
      ) : null}

      <span className={`flex flex-col gap-3.5 transition-[opacity,filter] duration-500 ${offline ? "opacity-40 saturate-0" : ""}`}>
        <span className="flex items-start gap-3">
          <span className={`grid size-9 shrink-0 place-items-center rounded-lg ring-1 ring-inset ${STATUS_TILE[node.status]}`}>
            <RoleIcon className="size-[18px]" aria-hidden="true" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-semibold text-slate-100">{node.display_name}</span>
            <span className="block truncate font-mono text-[11px] text-slate-500">
              {node.hostname} · {node.ip_address}
            </span>
          </span>
          <Badge
            tone={STATUS_BADGE_TONE[node.status]}
            leading={<StatusDot colorClass={statusStyle.dot} size="sm" pulse={node.status === "critical"} />}
          >
            {statusStyle.label}
          </Badge>
        </span>

        <span className="flex flex-wrap items-center gap-1.5">
          <span className="rounded bg-slate-800/70 px-1.5 py-0.5 font-mono text-[10px] tracking-wider text-slate-400 uppercase">
            {ROLE_LABELS[node.role]}
          </span>
          {node.simulated_incident ? (
            <Badge tone="crit" leading={<TriangleAlert className="size-3" aria-hidden="true" />}>
              {ANOMALY_LABELS[node.simulated_incident]}
            </Badge>
          ) : null}
          <span className="ml-auto font-mono text-[10px] text-slate-500">
            UP <span className="text-slate-300 tabular-nums">{offline ? "—" : formatUptime(node.uptime_seconds)}</span>
          </span>
        </span>

        <span className="flex flex-col gap-2.5">
          <MetricRow
            label="CPU"
            ariaLabel={`CPU load of ${node.display_name}`}
            valueText={cpuText}
            fraction={offline ? 0 : node.cpu_percent / 100}
            level={cpuLevel}
            markers={CPU_MARKERS}
          />
          <MetricRow
            label="RAM"
            ariaLabel={`Memory usage of ${node.display_name}`}
            valueText={memoryText}
            detail={memoryDetail}
            fraction={offline ? 0 : node.memory_percent / 100}
            level={memoryLevel}
            markers={MEMORY_MARKERS}
          />
          <MetricRow
            label="NVMe"
            ariaLabel={`Storage usage of ${node.display_name}`}
            valueText={diskText}
            fraction={offline ? 0 : node.disk_percent / 100}
            level={diskLevel}
            markers={DISK_MARKERS}
          />
          <MetricRow
            label="Temp"
            ariaLabel={`Temperature of ${node.display_name}`}
            valueText={temperatureText}
            fraction={temperature === null ? 0 : temperatureFraction(temperature)}
            level={temperatureLevel}
            markers={TEMPERATURE_MARKERS}
          />
          <MetricRow
            label="Latency"
            ariaLabel={`Network latency of ${node.display_name}`}
            valueText={latencyText}
            fraction={latency === null ? 0 : latencyFraction(latency)}
            level={latencyLevel}
            markers={LATENCY_MARKERS}
          />
        </span>

        <span className="flex items-end gap-3 border-t border-noc-border/70 pt-2.5">
          <span className="min-w-0 flex-1">
            <span className="mb-0.5 block font-mono text-[10px] tracking-[0.14em] text-slate-600 uppercase">CPU · 60 s</span>
            <Sparkline values={cpuSeries} color={LEVEL_HEX[cpuLevel]} min={0} max={100} className="h-8 w-full" />
          </span>
          <span className="flex shrink-0 flex-col gap-1 font-mono text-[11px] tabular-nums">
            <span className="flex items-center justify-end gap-1 text-slate-300">
              <ArrowUp className="size-3 text-violet-400" aria-hidden="true" />
              {offline ? "—" : formatBandwidth(node.net_upload_kbps)}
            </span>
            <span className="flex items-center justify-end gap-1 text-slate-300">
              <ArrowDown className="size-3 text-cyan-400" aria-hidden="true" />
              {offline ? "—" : formatBandwidth(node.net_download_kbps)}
            </span>
          </span>
        </span>
      </span>

      {offline ? (
        <span aria-hidden="true" className="pointer-events-none absolute inset-0 grid place-items-center">
          <span className="rounded border border-slate-500/50 bg-black/70 px-3 py-1 font-mono text-xs font-semibold tracking-[0.3em] text-slate-300">
            UNREACHABLE
          </span>
        </span>
      ) : null}
    </button>
  );
}

export const NodeCard = memo(NodeCardImpl);
