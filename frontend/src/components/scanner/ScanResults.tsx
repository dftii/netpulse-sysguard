import type { ReactNode } from "react";
import { CircleCheck, CircleX, ShieldAlert, ShieldCheck } from "lucide-react";
import { formatDateTime, formatLatency } from "../../lib/format";
import { RISK_STYLES } from "../../lib/thresholds";
import type { PortAuditRead, PortFindingRead, RiskLevel } from "../../types/api";
import { RiskBadge } from "./RiskBadge";
import { RISK_ACCENT, RISK_ORDER, formatDuration, sortFindings } from "./scanFormat";

interface ScanResultsProps {
  audit: PortAuditRead;
}

const GAUGE_RADIUS = 40;
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS;

function RiskGauge({ score, level }: { score: number; level: RiskLevel }) {
  const clamped = Math.min(100, Math.max(0, score));
  const offset = GAUGE_CIRCUMFERENCE * (1 - clamped / 100);
  return (
    <div className={`relative size-28 shrink-0 ${RISK_STYLES[level].text}`}>
      <svg viewBox="0 0 100 100" className="size-full -rotate-90" role="img" aria-label={`Risk score ${clamped.toFixed(0)} out of 100`}>
        <circle cx="50" cy="50" r={GAUGE_RADIUS} fill="none" strokeWidth="8" className="stroke-noc-grid" />
        <circle
          cx="50"
          cy="50"
          r={GAUGE_RADIUS}
          fill="none"
          strokeWidth="8"
          strokeLinecap="round"
          stroke="currentColor"
          strokeDasharray={GAUGE_CIRCUMFERENCE}
          strokeDashoffset={offset}
          className="transition-[stroke-dashoffset] duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-2xl leading-none font-semibold tabular-nums">{clamped.toFixed(0)}</span>
        <span className="mt-1 text-[10px] tracking-widest text-slate-500 uppercase">of 100</span>
      </div>
    </div>
  );
}

function Stat({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="rounded-md border border-noc-border bg-black/30 px-3 py-2">
      <dt className="text-[10px] tracking-widest text-slate-500 uppercase">{label}</dt>
      <dd className="mt-0.5 font-mono text-sm text-slate-200 tabular-nums">{children}</dd>
    </div>
  );
}

function FindingCard({ finding }: { finding: PortFindingRead }) {
  const urgent = finding.risk_level === "critical" || finding.risk_level === "high";
  const stateClass =
    finding.state === "open" ? "text-emerald-300" : finding.state === "filtered" ? "text-amber-300" : "text-slate-500";
  return (
    <li className={`rounded-lg border border-noc-border border-l-4 bg-noc-panel-2/60 p-3 ${RISK_ACCENT[finding.risk_level]}`}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="font-mono text-sm font-semibold text-white">
          {finding.port}/{finding.protocol}
        </span>
        <span className="font-mono text-xs text-slate-300">{finding.service}</span>
        <span className={`font-mono text-[11px] uppercase ${stateClass}`}>{finding.state}</span>
        <RiskBadge level={finding.risk_level} />
        <span className="ml-auto font-mono text-[11px] text-slate-500 tabular-nums">
          {finding.response_ms === null ? "no response time" : `${formatLatency(finding.response_ms)} response`}
        </span>
      </div>

      {finding.banner !== null && finding.banner !== "" && (
        <p className="mt-2 rounded border border-noc-border bg-black/40 px-2 py-1 font-mono text-[11px] break-all text-slate-400">
          <span className="text-slate-600">banner&nbsp;</span>
          {finding.banner}
        </p>
      )}

      <p className="mt-2 text-xs leading-relaxed text-slate-400">
        <span className="font-semibold text-slate-300">Why it matters. </span>
        {finding.risk_reason}
      </p>

      <div
        className={`mt-2 flex gap-2 rounded-md border px-2.5 py-2 text-xs leading-relaxed ${
          urgent ? "border-rose-500/30 bg-rose-500/5 text-rose-100" : "border-noc-accent/20 bg-noc-accent/5 text-cyan-100"
        }`}
      >
        {urgent ? (
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-rose-300" aria-hidden="true" />
        ) : (
          <ShieldCheck className="mt-0.5 size-4 shrink-0 text-noc-accent" aria-hidden="true" />
        )}
        <p>
          <span className="font-semibold">Recommendation. </span>
          {finding.recommendation}
        </p>
      </div>
    </li>
  );
}

/** Summary tiles, risk gauge and one card per finding (critical first). */
export function ScanResults({ audit }: ScanResultsProps) {
  const findings = sortFindings(audit.findings);
  const byLevel = findings.reduce<Partial<Record<RiskLevel, number>>>((acc, finding) => {
    acc[finding.risk_level] = (acc[finding.risk_level] ?? 0) + 1;
    return acc;
  }, {});
  const levels = (Object.keys(byLevel) as RiskLevel[]).sort((a, b) => RISK_ORDER[a] - RISK_ORDER[b]);

  return (
    <section aria-label={`Audit results for ${audit.target_host}`} className="space-y-4">
      <div className="flex flex-col gap-4 rounded-lg border border-noc-border bg-noc-panel-2/40 p-4 sm:flex-row sm:items-center">
        <div className="flex items-center gap-4">
          <RiskGauge score={audit.risk_score} level={audit.overall_risk} />
          <div className="sm:hidden">
            <p className="text-[10px] tracking-widest text-slate-500 uppercase">Overall risk</p>
            <RiskBadge level={audit.overall_risk} className="mt-1 text-xs" />
          </div>
        </div>

        <div className="min-w-0 flex-1">
          <div className="hidden items-center gap-2 sm:flex">
            <span className="text-[10px] tracking-widest text-slate-500 uppercase">Overall risk</span>
            <RiskBadge level={audit.overall_risk} className="text-xs" />
          </div>
          <p className="truncate font-mono text-sm text-white sm:mt-1">
            {audit.target_host}
            {audit.resolved_ip !== audit.target_host && <span className="text-slate-500"> [{audit.resolved_ip}]</span>}
          </p>
          <p className="font-mono text-[11px] text-slate-500">
            Audit #{audit.id} · {formatDateTime(audit.started_at)}
          </p>
          <dl className="mt-3 grid grid-cols-2 gap-2 lg:grid-cols-4">
            <Stat label="Host">
              {audit.host_reachable ? (
                <span className="inline-flex items-center gap-1 text-emerald-300">
                  <CircleCheck className="size-3.5" aria-hidden="true" /> reachable
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-rose-300">
                  <CircleX className="size-3.5" aria-hidden="true" /> unreachable
                </span>
              )}
            </Stat>
            <Stat label="Latency">{formatLatency(audit.host_latency_ms)}</Stat>
            <Stat label="Ports scanned">{audit.total_ports_scanned}</Stat>
            <Stat label="Open ports">
              <span className={audit.open_ports_count > 0 ? "text-amber-300" : "text-emerald-300"}>{audit.open_ports_count}</span>
            </Stat>
          </dl>
          <p className="mt-2 font-mono text-[11px] text-slate-500">Duration {formatDuration(audit.duration_ms)}</p>
        </div>
      </div>

      {levels.length > 0 && (
        <div className="flex flex-wrap items-center gap-2" aria-label="Findings by risk level">
          {levels.map((level) => (
            <span key={level} className="inline-flex items-center gap-1.5 text-xs text-slate-400">
              <RiskBadge level={level} />
              <span className="font-mono tabular-nums">x{byLevel[level]}</span>
            </span>
          ))}
        </div>
      )}

      {findings.length === 0 ? (
        <div className="flex items-start gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4 text-sm text-emerald-200">
          <ShieldCheck className="mt-0.5 size-5 shrink-0" aria-hidden="true" />
          <p>
            No open ports were found on the {audit.total_ports_scanned} audited ports. The attack surface of this host is minimal for
            the selected profile.
          </p>
        </div>
      ) : (
        <div>
          <h3 className="mb-2 flex items-center gap-2 text-[11px] font-semibold tracking-[0.18em] text-slate-400 uppercase">
            <ShieldAlert className="size-3.5" aria-hidden="true" />
            Findings and security recommendations
          </h3>
          <ul className="space-y-2">
            {findings.map((finding) => (
              <FindingCard key={`${finding.port}-${finding.protocol}`} finding={finding} />
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
