import { useEffect, useRef, useState } from "react";
import { CircleCheck, LoaderCircle, Syringe, TriangleAlert } from "lucide-react";
import { ANOMALY_LABELS } from "../../lib/format";
import { ANOMALY_TYPES, type AnomalyType, type NodeTelemetry } from "../../types/api";
import type { TelemetryController } from "../../types/dashboard";
import { errorMessage } from "./incidentMeta";

interface InjectIncidentFormProps {
  controller: TelemetryController;
}

type Feedback = { kind: "success" | "error"; text: string } | null;

const DURATIONS = [30, 60, 120] as const;
const FEEDBACK_MS = 6000;

/** Triggers a synthetic incident on one of the simulated cluster nodes. */
export function InjectIncidentForm({ controller }: InjectIncidentFormProps) {
  const [hostname, setHostname] = useState("");
  const [anomaly, setAnomaly] = useState<AnomalyType>("cpu_spike");
  const [duration, setDuration] = useState<number>(60);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const feedbackTimer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (feedbackTimer.current !== null) window.clearTimeout(feedbackTimer.current);
    },
    [],
  );

  const simulatedNodes: NodeTelemetry[] = controller.state.frame?.nodes.filter((node) => node.is_simulated) ?? [];
  const effectiveHost = simulatedNodes.some((node) => node.hostname === hostname) ? hostname : (simulatedNodes[0]?.hostname ?? "");
  const disabled = busy || effectiveHost === "";

  const showFeedback = (next: Feedback) => {
    if (feedbackTimer.current !== null) window.clearTimeout(feedbackTimer.current);
    setFeedback(next);
    feedbackTimer.current = window.setTimeout(() => setFeedback(null), FEEDBACK_MS);
  };

  const handleSubmit = async () => {
    if (disabled) return;
    setBusy(true);
    setFeedback(null);
    try {
      await controller.injectIncident({ hostname: effectiveHost, anomaly_type: anomaly, duration_seconds: duration });
      showFeedback({ kind: "success", text: `${ANOMALY_LABELS[anomaly]} injected on ${effectiveHost} for ${duration} s.` });
    } catch (error: unknown) {
      showFeedback({ kind: "error", text: errorMessage(error, "The incident could not be injected.") });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="rounded-lg border border-noc-border bg-black/30 p-3"
      aria-label="Inject incident"
      onSubmit={(event) => {
        event.preventDefault();
        void handleSubmit();
      }}
    >
      <h3 className="mb-2 flex items-center gap-2 text-[11px] font-semibold tracking-[0.18em] text-slate-400 uppercase">
        <Syringe className="size-3.5" aria-hidden="true" />
        Inject incident
        <span className="font-normal tracking-normal text-slate-600 normal-case">simulated nodes only</span>
      </h3>

      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <div className="flex flex-col gap-1">
          <label htmlFor="inject-node" className="text-[10px] tracking-wider text-slate-500 uppercase">
            Node
          </label>
          <select
            id="inject-node"
            className="noc-input"
            value={effectiveHost}
            disabled={busy || simulatedNodes.length === 0}
            onChange={(event) => setHostname(event.target.value)}
          >
            {simulatedNodes.length === 0 && <option value="">No simulated nodes</option>}
            {simulatedNodes.map((node) => (
              <option key={node.node_id} value={node.hostname}>
                {node.hostname}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="inject-type" className="text-[10px] tracking-wider text-slate-500 uppercase">
            Anomaly
          </label>
          <select
            id="inject-type"
            className="noc-input"
            value={anomaly}
            disabled={busy}
            onChange={(event) => setAnomaly(event.target.value as AnomalyType)}
          >
            {ANOMALY_TYPES.map((type) => (
              <option key={type} value={type}>
                {ANOMALY_LABELS[type]}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="inject-duration" className="text-[10px] tracking-wider text-slate-500 uppercase">
            Duration
          </label>
          <select
            id="inject-duration"
            className="noc-input"
            value={duration}
            disabled={busy}
            onChange={(event) => setDuration(Number(event.target.value))}
          >
            {DURATIONS.map((seconds) => (
              <option key={seconds} value={seconds}>
                {seconds} s
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-end">
          <button type="submit" className="noc-button noc-button-primary w-full" disabled={disabled}>
            {busy ? <LoaderCircle className="size-3.5 animate-spin" aria-hidden="true" /> : <Syringe className="size-3.5" aria-hidden="true" />}
            {busy ? "Injecting..." : "Inject"}
          </button>
        </div>
      </div>

      <div aria-live="polite" className="min-h-0">
        {feedback !== null && (
          <p
            role={feedback.kind === "error" ? "alert" : "status"}
            className={`mt-2 flex items-start gap-1.5 rounded border px-2 py-1 text-[11px] ${
              feedback.kind === "success"
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                : "border-rose-500/30 bg-rose-500/10 text-rose-200"
            }`}
          >
            {feedback.kind === "success" ? (
              <CircleCheck className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            ) : (
              <TriangleAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            )}
            {feedback.text}
          </p>
        )}
      </div>
    </form>
  );
}
