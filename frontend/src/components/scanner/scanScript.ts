/** Builds the nmap-style terminal lines of the scan console (header, probes, results and errors). */

import { formatClock, formatLatency } from "../../lib/format";
import { RISK_STYLES } from "../../lib/thresholds";
import { SourceError } from "../../services/telemetrySource";
import type { PortAuditRead } from "../../types/api";
import { formatDuration, sortFindings } from "./scanFormat";

export interface TermSegment {
  text: string;
  className?: string;
}

export interface TermLine {
  id: number;
  segments: TermSegment[];
}

export type Segments = TermSegment[];

const DIM = "text-slate-500";
const OK = "text-emerald-300";
const BAD = "text-rose-300";
const WARN = "text-amber-300";
const ACCENT = "text-cyan-300";

export function seg(text: string, className?: string): TermSegment {
  return className === undefined ? { text } : { text, className };
}

export function headerSegments(target: string, profileLabel: string, portCount: number): Segments[] {
  return [
    [seg("Starting NetPulse audit against ", DIM), seg(target, ACCENT), seg(` at ${formatClock(Date.now())} ...`, DIM)],
    [seg(`Profile: ${profileLabel} (${portCount} ports) | mode: TCP connect() | banner grab: on`, DIM)],
  ];
}

export function probeSegments(target: string, port: number): Segments {
  return [seg("probe ", DIM), seg(`${target}:${port}/tcp`, "text-slate-300"), seg(" ... ", DIM), seg("sent", "text-slate-400")];
}

export function waitingSegments(): Segments {
  return [seg("waiting for outstanding connections to complete ...", DIM)];
}

export function abortedSegments(): Segments[] {
  return [[seg("Scan aborted by operator. Partial results discarded.", WARN)]];
}

export function describeScanError(error: unknown): { title: string; hint: string } {
  if (error instanceof SourceError) {
    if (error.status === 400) {
      return {
        title: `Target rejected: ${error.message}`,
        hint: "Only private, loopback and link-local addresses can be audited unless the backend enables NETPULSE_SCAN_ALLOW_PUBLIC_TARGETS. Check the target and the port list.",
      };
    }
    if (error.status === 429) {
      return {
        title: `Scanner busy: ${error.message}`,
        hint: "The backend runs at most 2 audits at the same time. Wait for one to finish and launch again.",
      };
    }
    if (error.status === 404) {
      return {
        title: `Not found: ${error.message}`,
        hint: "The selected node no longer exists. Pick another node or type the address manually.",
      };
    }
    if (error.status === null) {
      return {
        title: `Scan failed: ${error.message}`,
        hint: "The backend could not be reached. Check that it is running or switch the dashboard to simulation mode.",
      };
    }
    return {
      title: `Scan failed (HTTP ${error.status}): ${error.message}`,
      hint: "The audit service returned an unexpected error. Check the backend logs and try again.",
    };
  }
  const message = error instanceof Error ? error.message : String(error);
  return { title: `Scan failed: ${message}`, hint: "Unexpected client error. Try again; if it persists, reload the dashboard." };
}

export function errorSegments(error: unknown): Segments[] {
  const { title, hint } = describeScanError(error);
  return [
    [seg("error: ", "text-rose-400 font-semibold"), seg(title, BAD)],
    [seg("hint:  ", DIM), seg(hint, "text-slate-400")],
  ];
}

function pad(value: string, width: number): string {
  return value.length >= width ? `${value} ` : value.padEnd(width);
}

/** The full nmap-like report for one audit. */
export function resultSegments(audit: PortAuditRead, label: string | null): Segments[] {
  const lines: Segments[] = [];
  const findings = sortFindings(audit.findings);
  const target = label === null ? audit.target_host : `${audit.target_host} (${label})`;

  lines.push([
    seg("Scan report for ", DIM),
    seg(target, ACCENT),
    seg(audit.resolved_ip === audit.target_host ? "" : ` [${audit.resolved_ip}]`, DIM),
  ]);
  if (audit.host_reachable) {
    lines.push([seg("Host is up", OK), seg(` (${formatLatency(audit.host_latency_ms)} latency).`, DIM)]);
  } else {
    lines.push([seg("Host seems down", BAD), seg(" (no TCP response on the probed ports).", DIM)]);
  }
  const hidden = Math.max(0, audit.total_ports_scanned - audit.open_ports_count);
  lines.push([seg(`Not shown: ${hidden} closed/filtered tcp ports`, DIM)]);

  if (findings.length > 0) {
    lines.push([seg(`${pad("PORT", 10)}${pad("STATE", 8)}${pad("SERVICE", 14)}RISK`, "text-slate-400 font-semibold")]);
    for (const finding of findings) {
      const style = RISK_STYLES[finding.risk_level];
      const stateClass = finding.state === "open" ? OK : finding.state === "filtered" ? WARN : DIM;
      lines.push([
        seg(pad(`${finding.port}/${finding.protocol}`, 10), "text-slate-200"),
        seg(pad(finding.state, 8), stateClass),
        seg(pad(finding.service, 14), "text-slate-300"),
        seg(`[${finding.risk_level.toUpperCase()}]`, `${style.text} font-semibold`),
      ]);
      if (finding.banner !== null && finding.banner !== "") {
        lines.push([seg("  |_ banner: ", DIM), seg(finding.banner, "text-slate-400")]);
      }
    }
  } else {
    lines.push([seg("No open ports found on the audited set.", OK)]);
  }

  const overall = RISK_STYLES[audit.overall_risk];
  lines.push([
    seg(`Audit #${audit.id} complete: `, DIM),
    seg(`${audit.open_ports_count} open / ${audit.total_ports_scanned} scanned`, "text-slate-300"),
    seg(` in ${formatDuration(audit.duration_ms)} | risk score `, DIM),
    seg(`${audit.risk_score.toFixed(1)}/100`, `${overall.text} font-semibold`),
    seg(` [${audit.overall_risk.toUpperCase()}]`, `${overall.text} font-semibold`),
  ]);
  return lines;
}
