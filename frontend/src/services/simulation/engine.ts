/**
 * Enterprise cluster simulator: a faithful TypeScript port of EnterpriseClusterSimulator in
 * backend/app/services/telemetry_collector.py.
 *
 * Every node follows a diurnal load curve plus mean-reverting (Ornstein-Uhlenbeck) noise and
 * occasional short bursts. An incident engine can drive any node into one of the seven anomaly
 * types (randomly, or on demand through `inject`). After an incident the forced metrics decay back
 * to baseline through per-metric residuals. Normal operation never crosses the critical ceilings,
 * so only incidents turn nodes critical.
 *
 * The engine is clock free: the caller supplies the timestamp of every tick, which lets the
 * simulation pre-warm with backdated samples and run headless in tests.
 */

import {
  ANOMALY_TYPES,
  type AnomalyType,
  type NodeStatus,
  type NodeTelemetry,
} from "../../types/api";
import { linkCapacityKbps, NODE_PROFILES, type NodeProfile } from "./profiles";
import type { Random } from "./random";

// Status thresholds (any single metric crossing a threshold escalates the node).
const CRITICAL_CPU = 90;
const CRITICAL_MEMORY = 92;
const CRITICAL_DISK = 95;
const CRITICAL_LATENCY_MS = 250;
const WARNING_CPU = 75;
const WARNING_MEMORY = 80;
const WARNING_DISK = 85;
const WARNING_LATENCY_MS = 120;

/**
 * Derive a node health status from its headline metrics.
 * A missing latency measurement is treated as healthy.
 */
export function classifyStatus(
  cpuPercent: number,
  memoryPercent: number,
  diskPercent: number,
  latencyMs: number | null,
): NodeStatus {
  const latency = latencyMs ?? 0;
  if (
    cpuPercent >= CRITICAL_CPU ||
    memoryPercent >= CRITICAL_MEMORY ||
    diskPercent >= CRITICAL_DISK ||
    latency >= CRITICAL_LATENCY_MS
  ) {
    return "critical";
  }
  if (
    cpuPercent >= WARNING_CPU ||
    memoryPercent >= WARNING_MEMORY ||
    diskPercent >= WARNING_DISK ||
    latency >= WARNING_LATENCY_MS
  ) {
    return "warning";
  }
  return "online";
}

function clamp(value: number, low: number, high: number): number {
  return Math.max(low, Math.min(high, value));
}

function roundTo(value: number, digits: number): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

/** Daily load curve in [-1, 1] from the wall clock; troughs at 03:00, peaks at 15:00. */
function diurnalFactor(at: Date): number {
  const hour = at.getHours() + at.getMinutes() / 60 + at.getSeconds() / 3600;
  return Math.sin((2 * Math.PI * (hour - 9)) / 24);
}

// Normal (non-incident) operation never exceeds these ceilings.
const NORMAL_CPU_CEILING = 88.5;
const NORMAL_MEMORY_CEILING = 88;
const NORMAL_DISK_CEILING = 90;
const NORMAL_NET_CEILING_FRACTION = 0.8; // per direction, below the 85 % saturation limit
const NORMAL_LATENCY_CEILING_MS = 15;
const NORMAL_TEMPERATURE_CEILING_C = 78; // stays below the 80 C anomaly warning threshold
const DISK_CLEANUP_THRESHOLD = 84;
const DISK_CLEANUP_DROP = 6;

// Thermal spike (cooling failure) incident.
const THERMAL_TARGET_MIN_C = 91;
const THERMAL_TARGET_MAX_C = 98;
const THERMAL_TARGET_JITTER_C = 0.3;
const THERMAL_INCIDENT_MIN_C = 88;
const THERMAL_INCIDENT_MAX_C = 105;
const THERMAL_RISE_RATE = 0.6; // fraction of the gap to the target closed per tick
const THERMAL_NOISE_SCALE = 0.5; // sensor noise is damped while the heat sink is saturated
const TEMPERATURE_RELAX_RATE = 0.15; // fraction of the gap to the load-driven target closed per tick
const COOLING_CPU_RESIDUAL = 0.5; // CPU residual (points) above which load may legitimately run hot

type Metric = "cpu" | "memory" | "disk" | "upload" | "download" | "latency";
type MetricValues = Record<Metric, number>;

/** Per-tick decay of the post-incident residual for each metric (smooth recovery). */
const RESIDUAL_DECAY: Readonly<MetricValues> = {
  cpu: 0.8,
  memory: 0.85,
  disk: 0.94,
  upload: 0.75,
  download: 0.75,
  latency: 0.6,
};

const METRICS: readonly Metric[] = ["cpu", "memory", "disk", "upload", "download", "latency"];

interface Incident {
  kind: AnomalyType;
  remaining: number;
  target: number;
  rate: number;
  value: number;
}

interface SimSample {
  cpuPercent: number;
  memoryPercent: number;
  diskPercent: number;
  latencyMs: number | null;
  netUploadKbps: number;
  netDownloadKbps: number;
  processCount: number;
  temperatureC: number | null;
  uptimeSeconds: number;
  incident: AnomalyType | null;
}

/** Mutable state of one simulated node (noise processes, bursts, incident, residuals). */
class SimNode {
  readonly profile: NodeProfile;
  private readonly rng: Random;
  private readonly intervalSeconds: number;
  incidentProbability: number;
  private readonly burstScale: number;
  private bootOffsetSeconds: number;

  private diskLevel: number;
  private lastDiskPercent: number;
  private temperature: number;
  private cpuNoise = 0;
  private memoryNoise = 0;
  private uploadNoise = 0;
  private downloadNoise = 0;
  private latencyNoise = 0;
  private processNoise = 0;
  private temperatureNoise = 0;
  private burstLeft = 0;
  private burstTotal = 0;
  private burstPeak = 0;
  incident: Incident | null = null;
  private pending: { kind: AnomalyType; ticks: number } | null = null;
  private readonly residual: MetricValues = {
    cpu: 0,
    memory: 0,
    disk: 0,
    upload: 0,
    download: 0,
    latency: 0,
  };

  constructor(
    profile: NodeProfile,
    rng: Random,
    intervalSeconds: number,
    incidentProbability: number,
    burstScale: number,
  ) {
    this.profile = profile;
    this.rng = rng;
    this.intervalSeconds = intervalSeconds;
    this.incidentProbability = incidentProbability;
    this.burstScale = burstScale;
    this.bootOffsetSeconds = rng.uniform(2, 120) * 86400;
    this.diskLevel = profile.baseDisk;
    this.lastDiskPercent = profile.baseDisk;
    this.temperature = profile.tempIdleC + profile.tempLoadC * (profile.baseCpu / 100);
  }

  queue(kind: AnomalyType, ticks: number): void {
    this.pending = { kind, ticks };
  }

  // -- helpers ---------------------------------------------------------

  /** One Ornstein-Uhlenbeck step with long-run mean zero. */
  private ou(value: number, theta: number, sigma: number): number {
    return value - theta * value + sigma * this.rng.gauss();
  }

  /** Smooth 0..1..0 envelope of an occasional short burst (0 when no burst is running). */
  private burstEnvelope(): number {
    if (this.burstLeft <= 0) {
      if (this.rng.next() >= this.profile.burstProbability) {
        return 0;
      }
      this.burstTotal = this.rng.int(4, 12);
      this.burstLeft = this.burstTotal;
      this.burstPeak = this.rng.uniform(0.5, 1);
    }
    const progress = (this.burstTotal - this.burstLeft + 0.5) / this.burstTotal;
    this.burstLeft -= 1;
    return this.burstPeak * Math.sin(Math.PI * progress);
  }

  private startIncident(kind: AnomalyType, ticks: number, memoryNow: number, diskNow: number): void {
    const rng = this.rng;
    const incident: Incident = { kind, remaining: Math.max(1, ticks), target: 0, rate: 0, value: 0 };
    switch (kind) {
      case "cpu_spike":
        incident.target = rng.uniform(93, 99);
        break;
      case "memory_leak":
        incident.target = rng.uniform(95.5, 97.5);
        incident.rate = rng.uniform(0.4, 0.8);
        incident.value = memoryNow;
        break;
      case "bandwidth_saturation":
        incident.target = rng.uniform(0.88, 0.99);
        break;
      case "critical_latency":
        incident.target = rng.uniform(280, 700);
        break;
      case "disk_pressure":
        incident.target = rng.uniform(93, 98);
        incident.value = diskNow;
        incident.rate = Math.max(0.15, (incident.target - diskNow) / Math.max(1, incident.remaining * 0.5));
        break;
      case "thermal_spike":
        incident.target = rng.uniform(THERMAL_TARGET_MIN_C, THERMAL_TARGET_MAX_C);
        incident.value = this.temperature;
        break;
      case "service_down":
        incident.target = 0; // the node is unreachable: there is no metric to drive
        break;
    }
    this.incident = incident;
  }

  /**
   * Forced metric values for this tick of an active incident. SERVICE_DOWN and THERMAL_SPIKE force
   * no residual-tracked metric: an outage replaces the whole sample and a thermal spike drives the
   * temperature model directly (`incident.value` holds this tick's temperature target).
   */
  private applyIncident(incident: Incident): Partial<MetricValues> {
    const rng = this.rng;
    const capacityKbps = linkCapacityKbps(this.profile);
    const forced: Partial<MetricValues> = {};
    switch (incident.kind) {
      case "cpu_spike":
        forced.cpu = clamp(incident.target + rng.uniform(-1.5, 1.5), 91, 100);
        break;
      case "memory_leak":
        incident.value = Math.min(incident.target, incident.value + incident.rate);
        forced.memory = incident.value;
        break;
      case "bandwidth_saturation": {
        const up = clamp(incident.target + rng.uniform(-0.02, 0.02), 0.86, 0.995);
        const down = clamp(incident.target + rng.uniform(-0.02, 0.02), 0.86, 0.995);
        forced.upload = capacityKbps * up;
        forced.download = capacityKbps * down;
        break;
      }
      case "critical_latency":
        forced.latency = clamp(incident.target + rng.gauss(0, incident.target * 0.08), 280, 900);
        break;
      case "disk_pressure":
        incident.value = Math.min(incident.target, incident.value + incident.rate);
        forced.disk = incident.value;
        break;
      case "thermal_spike":
        incident.value = clamp(
          incident.target + rng.uniform(-THERMAL_TARGET_JITTER_C, THERMAL_TARGET_JITTER_C),
          THERMAL_INCIDENT_MIN_C,
          THERMAL_INCIDENT_MAX_C,
        );
        break;
      case "service_down":
        break;
    }
    return forced;
  }

  /**
   * Sample of a node whose service is down. Internal dynamics keep evolving but nothing is fed to
   * the residual mechanism, so the node resumes its baseline right after the outage. The boot
   * offset is re-anchored every offline tick, which makes uptime restart from zero.
   */
  private offlineSample(uptimeElapsed: number): SimSample {
    for (const metric of METRICS) {
      this.residual[metric] = 0;
    }
    this.temperature += TEMPERATURE_RELAX_RATE * (this.profile.tempIdleC - this.temperature);
    this.bootOffsetSeconds = -uptimeElapsed;
    return {
      cpuPercent: 0,
      memoryPercent: 0,
      diskPercent: roundTo(this.lastDiskPercent, 3),
      latencyMs: null,
      netUploadKbps: 0,
      netDownloadKbps: 0,
      processCount: 0,
      temperatureC: null,
      uptimeSeconds: 0,
      incident: "service_down",
    };
  }

  /**
   * Advance the chassis temperature model one tick and return the sensor reading. A thermal spike
   * pulls the temperature quickly towards its target; otherwise it relaxes towards a load-driven
   * target that stays under the normal ceiling unless an incident influences the load.
   */
  private nextTemperature(cpu: number, thermalTarget: number | null, cpuForced: boolean): number {
    const p = this.profile;
    if (thermalTarget !== null) {
      this.temperature += THERMAL_RISE_RATE * (thermalTarget - this.temperature);
      const reading = this.temperature + THERMAL_NOISE_SCALE * this.temperatureNoise;
      return Math.min(reading, THERMAL_INCIDENT_MAX_C);
    }

    let target = p.tempIdleC + (p.tempLoadC * cpu) / 100;
    const loadIsNormal = !cpuForced && Math.abs(this.residual.cpu) <= COOLING_CPU_RESIDUAL;
    if (loadIsNormal) {
      target = Math.min(target, NORMAL_TEMPERATURE_CEILING_C);
    }
    this.temperature += TEMPERATURE_RELAX_RATE * (target - this.temperature);
    let reading = this.temperature + this.temperatureNoise;
    if (loadIsNormal && this.temperature <= NORMAL_TEMPERATURE_CEILING_C) {
      reading = Math.min(reading, NORMAL_TEMPERATURE_CEILING_C);
    }
    return reading;
  }

  // -- main step -------------------------------------------------------

  step(diurnal: number, uptimeElapsed: number): SimSample {
    const p = this.profile;
    const rng = this.rng;

    // Baseline dynamics: diurnal curve + mean-reverting noise + occasional bursts.
    this.cpuNoise = this.ou(this.cpuNoise, 0.15, p.cpuSigma);
    this.memoryNoise = this.ou(this.memoryNoise, 0.05, 0.25);
    this.uploadNoise = this.ou(this.uploadNoise, 0.2, 0.06);
    this.downloadNoise = this.ou(this.downloadNoise, 0.2, 0.06);
    this.latencyNoise = this.ou(this.latencyNoise, 0.3, p.baseLatencyMs * 0.08);
    this.processNoise = this.ou(this.processNoise, 0.1, 1.5);
    this.temperatureNoise = this.ou(this.temperatureNoise, 0.25, 0.3);
    const burst = this.burstEnvelope() * this.burstScale;

    this.diskLevel += p.diskGrowthPerSecond * this.intervalSeconds;
    if (this.diskLevel > DISK_CLEANUP_THRESHOLD) {
      this.diskLevel -= DISK_CLEANUP_DROP; // log rotation / snapshot pruning
    }

    const capacityKbps = linkCapacityKbps(p);
    const netCeiling = capacityKbps * NORMAL_NET_CEILING_FRACTION;
    const netFactorBase = 1 + p.netDiurnal * diurnal + 0.5 * burst;

    const normal: MetricValues = {
      cpu: clamp(
        p.baseCpu + p.cpuDiurnal * diurnal + this.cpuNoise + p.burstMagnitude * burst,
        1,
        NORMAL_CPU_CEILING,
      ),
      memory: clamp(p.baseMemory + 2 * diurnal + this.memoryNoise, 5, NORMAL_MEMORY_CEILING),
      disk: clamp(this.diskLevel + rng.gauss(0, 0.01), 1, NORMAL_DISK_CEILING),
      upload: clamp(
        capacityKbps * p.baseUploadFraction * Math.max(0.05, netFactorBase + this.uploadNoise),
        0,
        netCeiling,
      ),
      download: clamp(
        capacityKbps * p.baseDownloadFraction * Math.max(0.05, netFactorBase + this.downloadNoise),
        0,
        netCeiling,
      ),
      latency: clamp(
        p.baseLatencyMs + this.latencyNoise + Math.abs(rng.gauss(0, p.baseLatencyMs * 0.1)),
        0.2,
        NORMAL_LATENCY_CEILING_MS,
      ),
    };

    // Incident lifecycle: a queued injection wins over random starts.
    if (this.pending !== null) {
      const { kind, ticks } = this.pending;
      this.pending = null;
      this.startIncident(kind, ticks, normal.memory, normal.disk);
    } else if (
      this.incident === null &&
      this.incidentProbability > 0 &&
      rng.next() < this.incidentProbability
    ) {
      this.startIncident(rng.pick(ANOMALY_TYPES), rng.int(30, 120), normal.memory, normal.disk);
    }

    let activeKind: AnomalyType | null = null;
    let forced: Partial<MetricValues> = {};
    let restartService = false;
    let thermalTarget: number | null = null;
    if (this.incident !== null) {
      activeKind = this.incident.kind;
      forced = this.applyIncident(this.incident);
      if (activeKind === "thermal_spike") {
        thermalTarget = this.incident.value;
      }
      this.incident.remaining -= 1;
      if (this.incident.remaining <= 0) {
        restartService = activeKind === "memory_leak";
        this.incident = null;
      }
    }

    if (activeKind === "service_down") {
      return this.offlineSample(uptimeElapsed);
    }

    // Compose final values: during an incident the forced value wins; afterwards the residual
    // (forced - normal at the last incident tick) decays towards baseline.
    const final: MetricValues = { cpu: 0, memory: 0, disk: 0, upload: 0, download: 0, latency: 0 };
    for (const metric of METRICS) {
      const forcedValue = forced[metric];
      if (forcedValue !== undefined) {
        this.residual[metric] = forcedValue - normal[metric];
      } else {
        this.residual[metric] *= RESIDUAL_DECAY[metric];
        if (Math.abs(this.residual[metric]) < 1e-6) {
          this.residual[metric] = 0;
        }
      }
      final[metric] = normal[metric] + this.residual[metric];
    }
    if (restartService) {
      // The leaking service is "fixed" (restarted): memory drops to baseline on the next tick.
      this.residual.memory = 0;
    }

    const cpu = clamp(final.cpu, 0, 100);
    const memory = clamp(final.memory, 0, 100);
    const disk = clamp(final.disk, 0, 100);
    const upload = clamp(final.upload, 0, capacityKbps);
    const download = clamp(final.download, 0, capacityKbps);
    const latency = Math.max(0, final.latency);

    const processes = Math.max(1, Math.round(p.baseProcesses + p.processCpuFactor * cpu + this.processNoise));
    const temperature = this.nextTemperature(cpu, thermalTarget, forced.cpu !== undefined);
    this.lastDiskPercent = disk;

    return {
      cpuPercent: roundTo(cpu, 2),
      memoryPercent: roundTo(memory, 3),
      diskPercent: roundTo(disk, 3),
      latencyMs: roundTo(latency, 2),
      netUploadKbps: roundTo(upload, 1),
      netDownloadKbps: roundTo(download, 1),
      processCount: processes,
      temperatureC: roundTo(temperature, 1),
      uptimeSeconds: Math.max(0, this.bootOffsetSeconds + uptimeElapsed),
      incident: activeKind,
    };
  }
}

export interface ClusterEngineOptions {
  /** Pseudo-random source shared by every node (seed it for reproducible runs). */
  rng: Random;
  /** Seconds between ticks; drives disk growth and the conversion of incident durations. */
  intervalSeconds: number;
  /** Probability per node per tick of a random incident starting. */
  incidentProbability: number;
  /**
   * Multiplier of the amplitude of the short load bursts (default 1, identical to the backend
   * profiles). Lower values flatten the charts; the detector ignores short bursts at full scale.
   */
  burstScale?: number;
}

/** Generates telemetry for the eight simulated enterprise nodes with an incident engine. */
export class ClusterEngine {
  private readonly intervalSeconds: number;
  private readonly nodes: SimNode[];
  private readonly byHostname: Map<string, SimNode>;
  private elapsedSeconds = 0;

  constructor(options: ClusterEngineOptions) {
    this.intervalSeconds = options.intervalSeconds;
    this.nodes = NODE_PROFILES.map(
      (profile) =>
        new SimNode(
          profile,
          options.rng,
          options.intervalSeconds,
          options.incidentProbability,
          options.burstScale ?? 1,
        ),
    );
    this.byHostname = new Map(this.nodes.map((node) => [node.profile.hostname, node]));
  }

  get hostnames(): string[] {
    return this.nodes.map((node) => node.profile.hostname);
  }

  hasNode(hostname: string): boolean {
    return this.byHostname.has(hostname);
  }

  /** Change the random incident probability of every node (0 disables random incidents). */
  setIncidentProbability(probability: number): void {
    for (const node of this.nodes) {
      node.incidentProbability = probability;
    }
  }

  /** Incident currently running on a node, or null. */
  activeIncident(hostname: string): AnomalyType | null {
    return this.byHostname.get(hostname)?.incident?.kind ?? null;
  }

  /** Queue an incident that starts on the next tick and lasts `durationSeconds`. */
  inject(hostname: string, anomalyType: AnomalyType, durationSeconds: number): void {
    const node = this.byHostname.get(hostname);
    if (node === undefined) {
      throw new RangeError(`Unknown simulated node '${hostname}'`);
    }
    node.queue(anomalyType, Math.max(1, Math.round(durationSeconds / this.intervalSeconds)));
  }

  /** Advance every node by one tick; `at` is the timestamp stamped on all snapshots. */
  tick(at: Date): NodeTelemetry[] {
    const diurnal = diurnalFactor(at);
    this.elapsedSeconds += this.intervalSeconds;
    const timestamp = at.toISOString();
    return this.nodes.map((node) => {
      const sim = node.step(diurnal, this.elapsedSeconds);
      const profile = node.profile;
      const status: NodeStatus =
        sim.incident === "service_down"
          ? "offline"
          : classifyStatus(sim.cpuPercent, sim.memoryPercent, sim.diskPercent, sim.latencyMs);
      return {
        node_id: profile.id,
        hostname: profile.hostname,
        display_name: profile.displayName,
        role: profile.role,
        ip_address: profile.ipAddress,
        is_simulated: true,
        status,
        timestamp,
        cpu_percent: sim.cpuPercent,
        memory_percent: sim.memoryPercent,
        memory_used_mb: roundTo((profile.memoryTotalMb * sim.memoryPercent) / 100, 1),
        memory_total_mb: profile.memoryTotalMb,
        disk_percent: sim.diskPercent,
        latency_ms: sim.latencyMs,
        net_upload_kbps: sim.netUploadKbps,
        net_download_kbps: sim.netDownloadKbps,
        process_count: sim.processCount,
        temperature_c: sim.temperatureC,
        link_capacity_mbps: profile.linkCapacityMbps,
        uptime_seconds: sim.uptimeSeconds,
        simulated_incident: sim.incident,
      };
    });
  }
}
