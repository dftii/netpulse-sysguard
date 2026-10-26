/** Header action that downloads a technical JSON audit report of the cluster and its anomalies. */

import { CircleAlert, CircleCheck, FileDown, LoaderCircle } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  auditReportFilename,
  buildAuditReport,
  downloadJson,
  REPORT_PORT_AUDIT_LIMIT,
} from "../../lib/auditReport";
import type { PortAuditSummary } from "../../types/api";
import type { TelemetryController } from "../../types/dashboard";

type ExportPhase = "idle" | "busy" | "done" | "partial" | "error";

/** How long the success/error feedback stays visible. */
const FEEDBACK_MS = 4000;

const FEEDBACK_TEXT: Record<Exclude<ExportPhase, "idle" | "busy">, string> = {
  done: "Report saved",
  partial: "Saved without port audits",
  error: "Export failed",
};

const FEEDBACK_STYLE: Record<Exclude<ExportPhase, "idle" | "busy">, string> = {
  done: "text-emerald-300",
  partial: "text-amber-300",
  error: "text-rose-300",
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export interface ExportReportButtonProps {
  controller: TelemetryController;
}

export function ExportReportButton({ controller }: ExportReportButtonProps) {
  const [phase, setPhase] = useState<ExportPhase>("idle");
  const [detail, setDetail] = useState<string>("");
  const timerRef = useRef<number | null>(null);
  const mountedRef = useRef(true);
  /** Always points at the latest controller so the report reflects the state at download time. */
  const controllerRef = useRef(controller);

  useEffect(() => {
    controllerRef.current = controller;
  }, [controller]);

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      clearTimer();
    };
  }, [clearTimer]);

  const showFeedback = useCallback(
    (next: ExportPhase, message: string) => {
      if (!mountedRef.current) return;
      clearTimer();
      setPhase(next);
      setDetail(message);
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null;
        setPhase("idle");
        setDetail("");
      }, FEEDBACK_MS);
    },
    [clearTimer],
  );

  const handleExport = useCallback(async () => {
    clearTimer();
    setPhase("busy");
    setDetail("");

    let portScans: PortAuditSummary[] | null = null;
    let portScansError: string | null = null;
    try {
      portScans = await controllerRef.current.listPortScans(REPORT_PORT_AUDIT_LIMIT);
    } catch (error) {
      // The failure is already in the log console; the report still ships with an explicit error field.
      portScansError = errorMessage(error);
    }

    try {
      const current = controllerRef.current;
      const generatedAt = new Date();
      const filename = auditReportFilename(generatedAt);
      const report = buildAuditReport({
        state: current.state,
        mode: current.mode,
        portScans,
        portScansError,
        generatedAt,
      });
      downloadJson(filename, report);
      current.log("info", "operator", `Exported audit report ${filename}`);
      if (portScans === null) {
        showFeedback("partial", `Port audits unavailable: ${portScansError ?? "unknown error"}`);
      } else {
        showFeedback("done", filename);
      }
    } catch (error) {
      controllerRef.current.log("error", "operator", `Audit report export failed: ${errorMessage(error)}`);
      showFeedback("error", errorMessage(error));
    }
  }, [clearTimer, showFeedback]);

  const busy = phase === "busy";
  const disabled = controller.state.frame === null || busy;
  const feedbackPhase = phase === "idle" || phase === "busy" ? null : phase;

  return (
    <div className="flex items-center gap-2">
      <span
        role="status"
        aria-live="polite"
        className={`flex items-center gap-1 font-mono text-[11px] ${feedbackPhase === null ? "" : FEEDBACK_STYLE[feedbackPhase]}`}
        title={detail}
      >
        {feedbackPhase === "done" ? <CircleCheck className="size-3.5 shrink-0" aria-hidden="true" /> : null}
        {feedbackPhase === "partial" || feedbackPhase === "error" ? (
          <CircleAlert className="size-3.5 shrink-0" aria-hidden="true" />
        ) : null}
        {feedbackPhase === null ? null : <span className="hidden sm:inline">{FEEDBACK_TEXT[feedbackPhase]}</span>}
        {feedbackPhase === null ? null : <span className="sr-only sm:hidden">{FEEDBACK_TEXT[feedbackPhase]}</span>}
      </span>
      <button
        type="button"
        className="noc-button"
        onClick={() => {
          void handleExport();
        }}
        disabled={disabled}
        aria-busy={busy}
        aria-label="Export audit report as JSON"
        title={
          controller.state.frame === null
            ? "Waiting for the first telemetry frame"
            : "Download a technical JSON report of the cluster and detected anomalies"
        }
      >
        {busy ? (
          <LoaderCircle className="size-3.5 animate-spin text-noc-accent" aria-hidden="true" />
        ) : (
          <FileDown className="size-3.5" aria-hidden="true" />
        )}
        <span className="hidden min-[400px]:inline">Export report</span>
      </button>
    </div>
  );
}
