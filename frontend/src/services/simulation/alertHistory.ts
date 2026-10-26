/**
 * Seed incident history shown right after the simulation starts, so the incident panel is never
 * empty for a first-time visitor. Alerts are generated with the same fields, thresholds and message
 * wording as the live detector, spread over the last couple of hours; the older ones are already
 * acknowledged.
 */

import type { AlertSeverity, AnomalyAlertRead, AnomalyType } from "../../types/api";
import { type DetectorSettings, formatClause, formatDuration } from "./detector";
import { profileByHostname, type NodeProfile } from "./profiles";
import type { Random } from "./random";

interface HistorySpec {
  /** Approximate age of the alert in minutes (jittered by a few minutes). */
  minutesAgo: number;
  hostname: string;
  anomalyType: AnomalyType;
  acknowledged: boolean;
}

const HISTORY_SPECS: readonly HistorySpec[] = [
  { minutesAgo: 114, hostname: "nas-storage-01", anomalyType: "disk_pressure", acknowledged: true },
  { minutesAgo: 97, hostname: "web-app-01", anomalyType: "bandwidth_saturation", acknowledged: true },
  { minutesAgo: 82, hostname: "db-primary-01", anomalyType: "cpu_spike", acknowledged: true },
  { minutesAgo: 66, hostname: "cache-redis-01", anomalyType: "memory_leak", acknowledged: true },
  { minutesAgo: 49, hostname: "lb-edge-01", anomalyType: "critical_latency", acknowledged: true },
  { minutesAgo: 34, hostname: "ai-gpu-node-01", anomalyType: "thermal_spike", acknowledged: false },
  { minutesAgo: 22, hostname: "dc-ad-01", anomalyType: "service_down", acknowledged: false },
  { minutesAgo: 9, hostname: "fw-core-01", anomalyType: "cpu_spike", acknowledged: false },
];

type AlertBody = Pick<
  AnomalyAlertRead,
  | "severity"
  | "metric_name"
  | "observed_value"
  | "baseline_mean"
  | "baseline_std"
  | "z_score"
  | "threshold"
  | "message"
>;

function round(value: number, digits: number): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function zScore(value: number, mean: number, std: number): number {
  return (value - mean) / std;
}

function body(
  severity: AlertSeverity,
  metric: string,
  value: number,
  mean: number | null,
  std: number | null,
  z: number | null,
  threshold: number,
  message: string,
): AlertBody {
  return {
    severity,
    metric_name: metric,
    observed_value: round(value, 2),
    baseline_mean: mean === null ? null : round(mean, 3),
    baseline_std: std === null ? null : round(std, 3),
    z_score: z === null ? null : round(z, 3),
    threshold: round(threshold, 3),
    message,
  };
}

function buildBody(profile: NodeProfile, type: AnomalyType, rng: Random, cfg: DetectorSettings): AlertBody {
  const host = profile.hostname;
  switch (type) {
    case "cpu_spike": {
      const value = rng.uniform(93, 98.5);
      const mean = profile.baseCpu + rng.uniform(-2, 2);
      const std = profile.cpuSigma * rng.uniform(1.2, 1.8);
      const z = zScore(value, mean, std);
      const severity: AlertSeverity =
        value >= cfg.cpuCriticalPercent || z >= cfg.zscoreThreshold * 1.5 ? "critical" : "warning";
      const message = `CPU spike on ${host}: ${value.toFixed(1)}%${formatClause({ mean, std, z }, "%")}`;
      return body(severity, "cpu_percent", value, mean, std, z, cfg.zscoreThreshold, message);
    }
    case "memory_leak": {
      const current = rng.uniform(91, 96.5);
      const slope = rng.uniform(0.2, 0.45);
      const rSquared = rng.uniform(0.9, 0.99);
      const samples = cfg.memoryLeakWindow;
      const mean = current - (slope * (samples - 1)) / 2;
      const std = (slope * samples) / Math.sqrt(12);
      const severity: AlertSeverity = current >= 90 ? "critical" : "warning";
      const exhaustion = formatDuration(((100 - current) / slope) * cfg.telemetryIntervalSeconds);
      const message =
        `Possible memory leak on ${host}: memory at ${current.toFixed(1)}%, ` +
        `growing ${slope.toFixed(3)} points/sample over the last ${samples} samples ` +
        `(R²=${rSquared.toFixed(2)}), projected exhaustion in ~${exhaustion}`;
      return body(severity, "memory_percent", current, mean, std, null, cfg.memoryLeakMinSlope, message);
    }
    case "bandwidth_saturation": {
      const utilisation = rng.uniform(88, 97);
      const baseline = (profile.baseUploadFraction + profile.baseDownloadFraction) * 100;
      const std = baseline * 0.15;
      const z = zScore(utilisation, baseline, std);
      const severity: AlertSeverity = utilisation >= 95 ? "critical" : "warning";
      const throughput = `${((utilisation / 100) * profile.linkCapacityMbps).toFixed(1)} Mbps of ${profile.linkCapacityMbps} Mbps`;
      const message = `Bandwidth saturation on ${host}: link at ${utilisation.toFixed(1)}% (${throughput})${formatClause({ mean: baseline, std, z }, "%")}`;
      return body(severity, "net_utilization_percent", utilisation, baseline, std, z, cfg.bandwidthSaturationPercent, message);
    }
    case "critical_latency": {
      const value = rng.uniform(280, 620);
      const mean = profile.baseLatencyMs * 1.05;
      const std = Math.max(0.05, profile.baseLatencyMs * 0.12);
      const z = zScore(value, mean, std);
      const lead = [`limit ${cfg.latencyCriticalMs.toFixed(0)} ms`];
      const message = `Critical latency on ${host}: ${value.toFixed(1)} ms${formatClause({ mean, std, z }, " ms", lead)}`;
      return body("critical", "latency_ms", value, mean, std, z, cfg.latencyCriticalMs, message);
    }
    case "disk_pressure": {
      const value = rng.uniform(92.5, 96.5);
      const mean = profile.baseDisk;
      const std = rng.uniform(0.02, 0.05);
      const z = zScore(value, mean, std);
      const lead = [`limit ${cfg.diskCriticalPercent.toFixed(0)}%`];
      const message = `Disk pressure on ${host}: ${value.toFixed(1)}% full${formatClause({ mean, std, z }, "%", lead)}`;
      return body("critical", "disk_percent", value, mean, std, z, cfg.diskCriticalPercent, message);
    }
    case "thermal_spike": {
      const value = rng.uniform(90.5, 96);
      const mean = profile.tempIdleC + (profile.tempLoadC * profile.baseCpu) / 100;
      const std = rng.uniform(0.35, 0.6);
      const z = zScore(value, mean, std);
      const lead = [`limit ${cfg.temperatureCriticalC.toFixed(0)}°C`];
      const message = `Critical temperature on ${host}: ${value.toFixed(1)}°C${formatClause({ mean, std, z }, "°C", lead)}`;
      return body("critical", "temperature_c", value, mean, std, z, cfg.temperatureCriticalC, message);
    }
    case "service_down": {
      const samples = rng.int(cfg.serviceDownSamples, cfg.serviceDownSamples + 3);
      const downtime = formatDuration((samples - 1) * cfg.telemetryIntervalSeconds + cfg.telemetryIntervalSeconds);
      const message = `Service down on ${host}: node unreachable for ${samples} consecutive samples (~${downtime})`;
      return body("critical", "offline_samples", samples, null, null, null, cfg.serviceDownSamples, message);
    }
  }
}

/**
 * Build the seed history ending shortly before `nowMs`, using the detector `settings` the live
 * detector runs with. Alerts are returned oldest first with ascending ids drawn from `nextId`.
 */
export function generateAlertHistory(
  rng: Random,
  nowMs: number,
  nextId: () => number,
  settings: DetectorSettings,
): AnomalyAlertRead[] {
  const alerts: AnomalyAlertRead[] = [];
  for (const spec of HISTORY_SPECS) {
    const profile = profileByHostname(spec.hostname);
    if (profile === undefined) {
      continue;
    }
    const jitterMinutes = rng.uniform(-3, 3);
    const detectedMs = nowMs - (spec.minutesAgo + jitterMinutes) * 60_000;
    const acknowledgedMs = detectedMs + rng.uniform(1.5, 9) * 60_000;
    alerts.push({
      id: nextId(),
      node_id: profile.id,
      detected_at: new Date(detectedMs).toISOString(),
      anomaly_type: spec.anomalyType,
      ...buildBody(profile, spec.anomalyType, rng, settings),
      acknowledged: spec.acknowledged,
      acknowledged_at: spec.acknowledged ? new Date(acknowledgedMs).toISOString() : null,
      node_hostname: profile.hostname,
    });
  }
  return alerts;
}
