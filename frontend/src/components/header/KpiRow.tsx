/** Four headline KPIs derived from the latest frame and the rolling cluster history. */

import { ArrowDown, ArrowUp, Bell, BellRing, HeartPulse, Network, Timer } from "lucide-react";
import { useMemo } from "react";
import { formatBandwidth, formatUptime } from "../../lib/format";
import type { NodeTelemetry } from "../../types/api";
import type { TelemetryState } from "../../types/dashboard";
import { Sparkline } from "../charts/Sparkline";
import { KpiCard, type KpiTone } from "./KpiCard";

const SPARKLINE_POINTS = 60;

/** Mean uptime over the nodes that are reachable; offline nodes would report a meaningless counter. */
function averageUptime(nodes: readonly NodeTelemetry[]): number | null {
  const reachable = nodes.filter((n) => n.status !== "offline");
  if (reachable.length === 0) return null;
  return reachable.reduce((sum, n) => sum + n.uptime_seconds, 0) / reachable.length;
}

function formatMbpsValue(kbps: number): string {
  const mbps = kbps / 1000;
  return mbps.toLocaleString("en-US", { minimumFractionDigits: mbps < 100 ? 1 : 0, maximumFractionDigits: mbps < 100 ? 1 : 0 });
}

interface HealthBarProps {
  online: number;
  warning: number;
  critical: number;
  offline: number;
}

function HealthBar({ online, warning, critical, offline }: HealthBarProps) {
  const segments = [
    { key: "online", count: online, className: "bg-emerald-400" },
    { key: "warning", count: warning, className: "bg-amber-400" },
    { key: "critical", count: critical, className: "bg-rose-500" },
    { key: "offline", count: offline, className: "bg-slate-500" },
  ].filter((s) => s.count > 0);

  return (
    <div
      role="img"
      aria-label={`${online} online, ${warning} warning, ${critical} critical, ${offline} offline`}
      className="flex h-1.5 w-full gap-0.5 overflow-hidden rounded-full bg-slate-800/80"
    >
      {segments.map((s) => (
        <span
          key={s.key}
          className={`h-full transition-[flex-grow] duration-500 ${s.className}`}
          style={{ flexGrow: s.count, flexBasis: 0 }}
        />
      ))}
    </div>
  );
}

export interface KpiRowProps {
  state: TelemetryState;
}

export function KpiRow({ state }: KpiRowProps) {
  const summary = state.frame?.summary ?? null;
  const nodes = state.frame?.nodes;

  const bandwidthSeries = useMemo(
    () => state.clusterHistory.slice(-SPARKLINE_POINTS).map((p) => p.uploadMbps + p.downloadMbps),
    [state.clusterHistory],
  );

  const uptime = nodes ? averageUptime(nodes) : null;
  const totalKbps = summary ? summary.total_upload_kbps + summary.total_download_kbps : null;
  const unhealthy = summary ? summary.critical + summary.offline : 0;
  const alerts = summary?.unacknowledged_alerts ?? 0;

  const nodeTone: KpiTone = summary === null ? "neutral" : unhealthy > 0 ? "crit" : summary.warning > 0 ? "warn" : "ok";
  const alertTone: KpiTone = summary === null ? "neutral" : alerts > 0 ? "crit" : "ok";

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label="Average uptime"
        icon={Timer}
        value={uptime === null ? "—" : formatUptime(uptime)}
        caption={summary ? `Mean across ${nodes?.filter((n) => n.status !== "offline").length ?? 0} reachable nodes` : "Awaiting telemetry"}
      />

      <KpiCard
        label="Total bandwidth"
        icon={Network}
        value={totalKbps === null ? "—" : formatMbpsValue(totalKbps)}
        unit="Mbps"
        caption={
          summary ? (
            <span className="flex flex-wrap items-center gap-x-3 gap-y-0.5 font-mono tabular-nums">
              <span className="inline-flex items-center gap-1 text-slate-400">
                <ArrowUp className="size-3 text-violet-400" aria-hidden="true" />
                {formatBandwidth(summary.total_upload_kbps)}
              </span>
              <span className="inline-flex items-center gap-1 text-slate-400">
                <ArrowDown className="size-3 text-cyan-400" aria-hidden="true" />
                {formatBandwidth(summary.total_download_kbps)}
              </span>
            </span>
          ) : (
            "Awaiting telemetry"
          )
        }
      >
        <Sparkline values={bandwidthSeries} color="#22d3ee" className="h-7 w-full" ariaLabel="Cluster bandwidth over the last 60 seconds" />
      </KpiCard>

      <KpiCard
        label="Healthy nodes"
        icon={HeartPulse}
        tone={nodeTone}
        value={summary ? `${summary.online} / ${summary.total_nodes}` : "—"}
        caption={
          summary
            ? `${unhealthy} critical or offline · ${summary.warning} warning`
            : "Awaiting telemetry"
        }
      >
        {summary ? (
          <HealthBar online={summary.online} warning={summary.warning} critical={summary.critical} offline={summary.offline} />
        ) : null}
      </KpiCard>

      <KpiCard
        label="Active alerts"
        icon={alerts > 0 ? BellRing : Bell}
        tone={alertTone}
        value={summary ? String(alerts) : "—"}
        caption={
          summary ? (alerts > 0 ? "Awaiting acknowledgement" : "No open alerts") : "Awaiting telemetry"
        }
      />
    </div>
  );
}
