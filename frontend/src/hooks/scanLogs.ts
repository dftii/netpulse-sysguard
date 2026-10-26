/** Log-console lines produced by a port scan, kept apart from the hook so they stay pure and testable. */

import type { PortAuditRead, PortScanRequest, RiskLevel } from "../types/api";
import type { LogLevel } from "../types/dashboard";
import type { LogDraft } from "./telemetryReducer";

/** Size of the backend's built-in COMMON_PORTS list, scanned when a request names no ports. */
export const DEFAULT_SCAN_PORT_COUNT = 44;

const OVERALL_RISK_LEVEL: Record<RiskLevel, LogLevel> = {
  info: "info",
  low: "info",
  medium: "info",
  high: "warn",
  critical: "critical",
};

export function countScanPorts(request: PortScanRequest): number {
  if (request.ports && request.ports.length > 0) return new Set(request.ports).size;
  if (request.port_range) return Math.max(0, request.port_range[1] - request.port_range[0] + 1);
  return DEFAULT_SCAN_PORT_COUNT;
}

export function scanStartLog(request: PortScanRequest): LogDraft {
  return {
    level: "info",
    source: "scanner",
    host: request.target,
    message: `Scanning ${request.target} (${countScanPorts(request)} ports)…`,
  };
}

export function scanFailureLog(request: PortScanRequest, message: string, cancelled: boolean): LogDraft {
  return cancelled
    ? { level: "warn", source: "scanner", host: request.target, message: `Scan of ${request.target} cancelled` }
    : { level: "error", source: "scanner", host: request.target, message: `Scan of ${request.target} failed: ${message}` };
}

/** Summary line, an unreachable-host warning when relevant, and one line per high/critical open port. */
export function scanCompletionLogs(audit: PortAuditRead): LogDraft[] {
  const drafts: LogDraft[] = [];
  const host = audit.target_host;
  const seconds = (audit.duration_ms / 1000).toFixed(1);

  drafts.push({
    level: OVERALL_RISK_LEVEL[audit.overall_risk],
    source: "scanner",
    host,
    message:
      `Scan of ${host} (${audit.resolved_ip}) finished in ${seconds} s: ` +
      `${audit.open_ports_count}/${audit.total_ports_scanned} ports open, ` +
      `overall risk ${audit.overall_risk.toUpperCase()} (score ${audit.risk_score.toFixed(1)})`,
  });

  if (!audit.host_reachable) {
    drafts.push({ level: "warn", source: "scanner", host, message: `${host} did not answer the reachability probe` });
  }

  for (const finding of audit.findings) {
    if (finding.state !== "open") continue;
    if (finding.risk_level !== "high" && finding.risk_level !== "critical") continue;
    drafts.push({
      level: finding.risk_level === "critical" ? "critical" : "warn",
      source: "scanner",
      host,
      message: `${finding.port}/${finding.protocol} ${finding.service} [${finding.risk_level.toUpperCase()}] ${finding.risk_reason}`,
    });
  }
  return drafts;
}
