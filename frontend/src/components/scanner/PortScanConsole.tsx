import { useEffect, useRef, useState } from "react";
import { History, LoaderCircle, Play, Radar, Square } from "lucide-react";
import { formatClock } from "../../lib/format";
import type { NodeTelemetry, PortAuditRead, PortScanRequest } from "../../types/api";
import type { TelemetryController } from "../../types/dashboard";
import { RiskBadge } from "./RiskBadge";
import { ScanResults } from "./ScanResults";
import { ScanTerminal, type ScanPhase } from "./ScanTerminal";
import { PORT_PROFILES, COMMON_CATALOGUE_PORTS, QUICK_PORTS, parsePortSpec, validateTarget, type PortProfileId } from "./portSpec";
import {
  abortedSegments,
  errorSegments,
  headerSegments,
  probeSegments,
  resultSegments,
  seg,
  waitingSegments,
  type Segments,
  type TermLine,
} from "./scanScript";

interface PortScanConsoleProps {
  controller: TelemetryController;
  nodes: NodeTelemetry[];
  preselectedNodeId: number | null;
}

interface HistoryEntry {
  audit: PortAuditRead;
  label: string | null;
  completedAt: number;
}

const MAX_TERMINAL_LINES = 400;
const MAX_HISTORY = 5;
const PROBE_MIN_DELAY_MS = 60;
const PROBE_JITTER_MS = 60;
const PROGRESS_CEILING = 95;
const PROGRESS_EASE = 0.03;
const REVEAL_DELAY_MS = 45;
const WAITING_LINE_EVERY_TICKS = 14;

function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function PortScanConsole({ controller, nodes, preselectedNodeId }: PortScanConsoleProps) {
  const [selectedNodeId, setSelectedNodeId] = useState("");
  const [targetText, setTargetText] = useState("");
  const [profile, setProfile] = useState<PortProfileId>("common");
  const [customPorts, setCustomPorts] = useState("22,80,443");
  const [formError, setFormError] = useState<string | null>(null);

  const [lines, setLines] = useState<TermLine[]>([]);
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [progress, setProgress] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [audit, setAudit] = useState<PortAuditRead | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  const nextLineId = useRef(1);
  const runId = useRef(0);
  const abortRef = useRef<AbortController | null>(null);
  const probeTimer = useRef<number | null>(null);
  const revealTimer = useRef<number | null>(null);

  const busy = phase === "running" || phase === "revealing";

  // ---- Preselection coming from the node grid -------------------------------------------------
  const preselectedNode = preselectedNodeId === null ? undefined : nodes.find((node) => node.node_id === preselectedNodeId);
  const preselectedIp = preselectedNode?.ip_address ?? null;
  useEffect(() => {
    if (preselectedNodeId === null || preselectedIp === null) return;
    setSelectedNodeId(String(preselectedNodeId));
    setTargetText(preselectedIp);
    setFormError(null);
  }, [preselectedNodeId, preselectedIp]);

  // ---- Lifecycle: abort and clear timers on unmount ---------------------------------------------
  useEffect(
    () => () => {
      runId.current += 1;
      abortRef.current?.abort();
      abortRef.current = null;
      if (probeTimer.current !== null) window.clearTimeout(probeTimer.current);
      if (revealTimer.current !== null) window.clearTimeout(revealTimer.current);
    },
    [],
  );

  // ---- Terminal helpers ---------------------------------------------------------------------------
  const makeLines = (segments: Segments[]): TermLine[] =>
    segments.map((lineSegments) => {
      const id = nextLineId.current;
      nextLineId.current += 1;
      return { id, segments: lineSegments };
    });

  const appendLines = (segments: Segments[]) => {
    const created = makeLines(segments);
    setLines((previous) => [...previous, ...created].slice(-MAX_TERMINAL_LINES));
  };

  const clearTimers = () => {
    if (probeTimer.current !== null) window.clearTimeout(probeTimer.current);
    if (revealTimer.current !== null) window.clearTimeout(revealTimer.current);
    probeTimer.current = null;
    revealTimer.current = null;
  };

  // ---- Probe animation (runs while the request is pending) ---------------------------------------
  const startProbeAnimation = (target: string, ports: readonly number[], myRun: number) => {
    const startedAt = performance.now();
    let index = 0;
    let level = 0;
    let idleTicks = 0;

    const tick = () => {
      if (runId.current !== myRun) return;
      level += (PROGRESS_CEILING - level) * PROGRESS_EASE;
      setProgress(level);
      setElapsedMs(performance.now() - startedAt);

      const port = ports[index];
      if (port !== undefined) {
        appendLines([probeSegments(target, port)]);
        index += 1;
      } else {
        if (idleTicks % WAITING_LINE_EVERY_TICKS === 0) appendLines([waitingSegments()]);
        idleTicks += 1;
      }
      probeTimer.current = window.setTimeout(tick, PROBE_MIN_DELAY_MS + Math.random() * PROBE_JITTER_MS);
    };

    probeTimer.current = window.setTimeout(tick, PROBE_MIN_DELAY_MS);
  };

  // ---- Result reveal (line by line) ------------------------------------------------------------------
  const revealResult = (result: PortAuditRead, label: string | null, myRun: number) => {
    const script = resultSegments(result, label);
    setProgress(100);
    setPhase("revealing");
    setHistory((previous) =>
      [{ audit: result, label, completedAt: Date.now() }, ...previous.filter((entry) => entry.audit.id !== result.id)].slice(0, MAX_HISTORY),
    );

    const finish = () => {
      if (runId.current !== myRun) return;
      setAudit(result);
      setPhase("done");
    };

    if (prefersReducedMotion()) {
      appendLines(script);
      finish();
      return;
    }

    let cursor = 0;
    const step = () => {
      if (runId.current !== myRun) return;
      const next = script[cursor];
      if (next === undefined) {
        finish();
        return;
      }
      appendLines([next]);
      cursor += 1;
      revealTimer.current = window.setTimeout(step, REVEAL_DELAY_MS);
    };
    step();
  };

  // ---- Actions ---------------------------------------------------------------------------------------------
  const handleLaunch = async () => {
    if (busy) return;

    const targetError = validateTarget(targetText);
    if (targetError !== null) {
      setFormError(targetError);
      return;
    }

    let ports: number[] | null = null;
    if (profile === "quick") {
      ports = [...QUICK_PORTS];
    } else if (profile === "custom") {
      const parsed = parsePortSpec(customPorts);
      if (!parsed.ok) {
        setFormError(parsed.error);
        return;
      }
      ports = parsed.ports;
    }

    const target = targetText.trim();
    const matchedNode = nodes.find((node) => String(node.node_id) === selectedNodeId);
    const request: PortScanRequest = {
      target,
      node_id: matchedNode?.node_id ?? null,
      ...(ports === null ? {} : { ports }),
    };
    const label = matchedNode?.hostname ?? null;
    const animatedPorts = ports ?? COMMON_CATALOGUE_PORTS;
    const profileLabel = PORT_PROFILES.find((entry) => entry.id === profile)?.label ?? profile;

    clearTimers();
    abortRef.current?.abort();
    runId.current += 1;
    const myRun = runId.current;
    const abortController = new AbortController();
    abortRef.current = abortController;

    setFormError(null);
    setAudit(null);
    setProgress(0);
    setElapsedMs(0);
    setPhase("running");
    setLines(makeLines(headerSegments(target, profileLabel, animatedPorts.length)));
    startProbeAnimation(target, animatedPorts, myRun);

    try {
      const result = await controller.runPortScan(request, abortController.signal);
      if (runId.current !== myRun) return;
      clearTimers();
      revealResult(result, label, myRun);
    } catch (error: unknown) {
      if (runId.current !== myRun) return;
      clearTimers();
      appendLines(errorSegments(error));
      setPhase("error");
    } finally {
      if (abortRef.current === abortController) abortRef.current = null;
    }
  };

  const handleAbort = () => {
    if (phase !== "running") return;
    runId.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
    clearTimers();
    appendLines(abortedSegments());
    setProgress(0);
    setPhase("idle");
  };

  const handleReopen = (entry: HistoryEntry) => {
    if (busy) return;
    clearTimers();
    runId.current += 1;
    setLines(
      makeLines([
        [seg(`Reopened audit #${entry.audit.id} from history (completed ${formatClock(entry.completedAt)}).`, "text-slate-500")],
        ...resultSegments(entry.audit, entry.label),
      ]),
    );
    setAudit(entry.audit);
    setProgress(100);
    setPhase("done");
    setFormError(null);
  };

  const handleNodeSelect = (value: string) => {
    setSelectedNodeId(value);
    if (value === "") return;
    const node = nodes.find((candidate) => String(candidate.node_id) === value);
    if (node !== undefined) setTargetText(node.ip_address);
    setFormError(null);
  };

  const handleTargetChange = (value: string) => {
    setTargetText(value);
    const match = nodes.find((node) => node.ip_address === value.trim());
    setSelectedNodeId(match === undefined ? "" : String(match.node_id));
    setFormError(null);
  };

  const selectValue = nodes.some((node) => String(node.node_id) === selectedNodeId) ? selectedNodeId : "";
  const errorId = "scan-form-error";

  return (
    <section className="noc-panel" aria-labelledby="scan-console-title">
      <header className="noc-panel-header">
        <h2 id="scan-console-title" className="noc-title">
          <Radar className="size-4 text-noc-accent" aria-hidden="true" />
          Port audit console
        </h2>
        <span className="hidden text-[11px] text-slate-500 sm:inline">TCP connect scan · private ranges only</span>
      </header>

      <div className="space-y-4 p-4">
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            void handleLaunch();
          }}
        >
          <div className="grid gap-3 md:grid-cols-2">
            <div className="flex flex-col gap-1">
              <label htmlFor="scan-node" className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                Node
              </label>
              <select
                id="scan-node"
                className="noc-input"
                value={selectValue}
                disabled={busy}
                onChange={(event) => handleNodeSelect(event.target.value)}
              >
                <option value="">Custom target</option>
                {nodes.map((node) => (
                  <option key={node.node_id} value={String(node.node_id)}>
                    {node.display_name} — {node.ip_address}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex flex-col gap-1">
              <label htmlFor="scan-target" className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                Target IP / hostname
              </label>
              <input
                id="scan-target"
                className="noc-input"
                type="text"
                inputMode="url"
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                placeholder="10.20.4.11 or db-primary.lan"
                value={targetText}
                disabled={busy}
                aria-invalid={formError !== null && validateTarget(targetText) !== null}
                aria-describedby={formError !== null ? errorId : undefined}
                onChange={(event) => handleTargetChange(event.target.value)}
              />
            </div>
          </div>

          <fieldset disabled={busy} className="min-w-0">
            <legend className="mb-1 text-[11px] font-medium tracking-wider text-slate-400 uppercase">Port profile</legend>
            <div role="radiogroup" aria-label="Port profile" className="grid gap-2 sm:grid-cols-3">
              {PORT_PROFILES.map((entry) => {
                const active = entry.id === profile;
                return (
                  <label
                    key={entry.id}
                    className={`flex cursor-pointer flex-col rounded-md border px-3 py-2 transition has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-noc-accent/60 ${
                      active ? "border-noc-accent/60 bg-noc-accent/10" : "border-noc-border bg-black/30 hover:border-slate-600"
                    } ${busy ? "cursor-not-allowed opacity-60" : ""}`}
                  >
                    <input
                      type="radio"
                      name="scan-profile"
                      className="sr-only"
                      value={entry.id}
                      checked={active}
                      onChange={() => {
                        setProfile(entry.id);
                        setFormError(null);
                      }}
                    />
                    <span className={`text-xs font-semibold ${active ? "text-cyan-200" : "text-slate-200"}`}>{entry.label}</span>
                    <span className="text-[11px] text-slate-500">{entry.hint}</span>
                  </label>
                );
              })}
            </div>
          </fieldset>

          {profile === "custom" && (
            <div className="flex flex-col gap-1">
              <label htmlFor="scan-ports" className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                Ports (list or range, 1-65535, max 1024)
              </label>
              <input
                id="scan-ports"
                className="noc-input"
                type="text"
                autoComplete="off"
                spellCheck={false}
                placeholder="22,80,443 or 1-1024"
                value={customPorts}
                disabled={busy}
                aria-describedby={formError !== null ? errorId : undefined}
                onChange={(event) => {
                  setCustomPorts(event.target.value);
                  setFormError(null);
                }}
              />
            </div>
          )}

          {formError !== null && (
            <p id={errorId} role="alert" className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 font-mono text-xs text-rose-200">
              {formError}
            </p>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" className="noc-button noc-button-primary" disabled={busy}>
              {busy ? <LoaderCircle className="size-3.5 animate-spin" aria-hidden="true" /> : <Play className="size-3.5" aria-hidden="true" />}
              {busy ? "Scanning..." : "Launch scan"}
            </button>
            <button type="button" className="noc-button" onClick={handleAbort} disabled={phase !== "running"}>
              <Square className="size-3.5" aria-hidden="true" />
              Abort
            </button>
            <span className="text-[11px] text-slate-500" aria-live="polite">
              {phase === "running" && "Audit in progress"}
              {phase === "revealing" && "Receiving results"}
              {phase === "done" && "Audit complete"}
              {phase === "error" && "Audit failed"}
            </span>
          </div>
        </form>

        <ScanTerminal lines={lines} phase={phase} progress={progress} elapsedMs={elapsedMs} />

        {audit !== null && phase === "done" && <ScanResults audit={audit} />}

        {history.length > 0 && (
          <div>
            <h3 className="mb-2 flex items-center gap-2 text-[11px] font-semibold tracking-[0.18em] text-slate-400 uppercase">
              <History className="size-3.5" aria-hidden="true" />
              Recent audits ({history.length}/{MAX_HISTORY})
            </h3>
            <ul className="grid gap-2 md:grid-cols-2">
              {history.map((entry) => {
                const active = audit !== null && audit.id === entry.audit.id && phase === "done";
                return (
                  <li key={entry.audit.id}>
                    <button
                      type="button"
                      onClick={() => handleReopen(entry)}
                      disabled={busy}
                      aria-label={`Reopen audit ${entry.audit.id} for ${entry.audit.target_host}`}
                      aria-current={active ? "true" : undefined}
                      className={`flex w-full items-center gap-3 rounded-md border px-3 py-2 text-left transition focus-visible:ring-2 focus-visible:ring-noc-accent/60 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50 ${
                        active ? "border-noc-accent/60 bg-noc-accent/10" : "border-noc-border bg-black/30 hover:border-slate-600"
                      }`}
                    >
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-mono text-xs text-slate-200">
                          {entry.label ?? entry.audit.target_host}
                          {entry.label !== null && <span className="text-slate-500"> {entry.audit.target_host}</span>}
                        </span>
                        <span className="block font-mono text-[11px] text-slate-500">
                          #{entry.audit.id} · {entry.audit.open_ports_count} open / {entry.audit.total_ports_scanned} · {formatClock(entry.completedAt)}
                        </span>
                      </span>
                      <RiskBadge level={entry.audit.overall_risk} />
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}
