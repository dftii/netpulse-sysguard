import { memo, useState } from "react";
import { Check, CheckCheck, LoaderCircle, TriangleAlert } from "lucide-react";
import { ANOMALY_LABELS, formatDateTime } from "../../lib/format";
import { SEVERITY_STYLES } from "../../lib/thresholds";
import type { AnomalyAlertRead } from "../../types/api";
import { ANOMALY_ICONS, errorMessage, formatMetricValue, formatRelativeTime } from "./incidentMeta";

interface IncidentRowProps {
  alert: AnomalyAlertRead;
  flashing: boolean;
  nowMs: number;
  onAcknowledge: (alertId: number) => Promise<void>;
}

const ICON_TONE = {
  info: "border-sky-500/30 bg-sky-500/10 text-sky-300",
  warning: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  critical: "border-rose-500/40 bg-rose-500/10 text-rose-300",
} as const;

export const IncidentRow = memo(function IncidentRow({ alert, flashing, nowMs, onAcknowledge }: IncidentRowProps) {
  const [busy, setBusy] = useState(false);
  const [confirmedLocally, setConfirmedLocally] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const Icon = ANOMALY_ICONS[alert.anomaly_type];
  const severity = SEVERITY_STYLES[alert.severity];
  const acknowledged = alert.acknowledged || confirmedLocally;
  const host = alert.node_hostname ?? `node-${alert.node_id}`;

  const handleAcknowledge = async () => {
    setBusy(true);
    setError(null);
    try {
      await onAcknowledge(alert.id);
      setConfirmedLocally(true);
    } catch (caught: unknown) {
      setError(errorMessage(caught, "Could not acknowledge the alert."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <li
      className={`rounded-lg border bg-noc-panel-2/50 p-3 transition-[box-shadow,border-color] duration-700 ${
        flashing ? "border-noc-accent/70 shadow-[0_0_0_2px_rgb(34_211_238/0.45),0_0_18px_rgb(34_211_238/0.25)]" : "border-noc-border"
      } ${acknowledged ? "opacity-70" : ""}`}
      data-flashing={flashing ? "true" : undefined}
    >
      <div className="flex items-start gap-3">
        <span className={`mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md border ${ICON_TONE[alert.severity]}`}>
          <Icon className="size-4" aria-hidden="true" />
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span
              className={`inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase ring-1 ring-inset ${severity.badge}`}
            >
              {alert.severity}
            </span>
            <span className="text-xs font-semibold text-slate-200">{ANOMALY_LABELS[alert.anomaly_type]}</span>
            <span className="font-mono text-xs text-noc-accent">{host}</span>
            {flashing && <span className="text-[10px] font-semibold tracking-widest text-noc-accent uppercase">new</span>}
          </div>

          <p className="mt-1 text-xs leading-relaxed break-words text-slate-300">{alert.message}</p>

          <dl className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-slate-500">
            <div className="flex gap-1">
              <dt>{alert.metric_name}</dt>
              <dd>
                <span className={severity.text}>{formatMetricValue(alert.observed_value)}</span>
                <span> / thr {formatMetricValue(alert.threshold)}</span>
              </dd>
            </div>
            {alert.z_score !== null && (
              <div className="flex gap-1">
                <dt>z-score</dt>
                <dd className="text-slate-300">{alert.z_score.toFixed(2)}</dd>
              </div>
            )}
            {alert.baseline_mean !== null && (
              <div className="flex gap-1">
                <dt>baseline</dt>
                <dd className="text-slate-300">
                  {formatMetricValue(alert.baseline_mean)}
                  {alert.baseline_std !== null && ` ± ${formatMetricValue(alert.baseline_std)}`}
                </dd>
              </div>
            )}
          </dl>

          <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
            <time dateTime={alert.detected_at} title={formatDateTime(alert.detected_at)} className="font-mono text-[11px] text-slate-500">
              {formatRelativeTime(alert.detected_at, nowMs)} · {formatDateTime(alert.detected_at)}
            </time>

            {acknowledged ? (
              <span className="inline-flex items-center gap-1 text-[11px] text-emerald-300">
                <CheckCheck className="size-3.5" aria-hidden="true" />
                Acknowledged
                {alert.acknowledged_at !== null && (
                  <span className="font-mono text-slate-500"> {formatDateTime(alert.acknowledged_at)}</span>
                )}
              </span>
            ) : (
              <button
                type="button"
                className="noc-button"
                disabled={busy}
                onClick={() => void handleAcknowledge()}
                aria-label={`Acknowledge ${ANOMALY_LABELS[alert.anomaly_type]} alert on ${host}`}
              >
                {busy ? <LoaderCircle className="size-3.5 animate-spin" aria-hidden="true" /> : <Check className="size-3.5" aria-hidden="true" />}
                {busy ? "Acknowledging..." : "Acknowledge"}
              </button>
            )}
          </div>

          {error !== null && (
            <p role="alert" className="mt-2 flex items-start gap-1.5 rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200">
              <TriangleAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
              {error}
            </p>
          )}
        </div>
      </div>
    </li>
  );
});
