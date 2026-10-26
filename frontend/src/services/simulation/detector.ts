/**
 * Statistical anomaly detection engine: a TypeScript port of backend/app/services/anomaly_detector.py.
 *
 * The detector keeps a bounded rolling baseline per node and per metric and combines z-score
 * analysis, absolute thresholds and a linear-regression trend test:
 *
 *  - cpu_spike             z-score outlier (with an absolute floor) or sustained critical load
 *  - memory_leak           steady, strongly linear growth of memory utilisation
 *  - bandwidth_saturation  link utilisation above a limit, or a traffic burst on a busy link
 *  - critical_latency      absolute latency limit or a large relative jump
 *  - disk_pressure         absolute fill level or a sudden jump on an already full disk
 *  - thermal_spike         absolute temperature limits or a sudden rise towards a hot operating point
 *  - service_down          node unreachable (offline) for several consecutive samples
 *
 * Offline samples carry placeholder metrics, so they only feed the service-down counter: they never
 * reach a baseline and no other evaluator runs for them. Z-scores are computed against the baseline
 * before the new sample joins it, and anomalous samples are withheld from the baseline ("baseline
 * freezing") until the anomaly outlives the window and becomes the new normal.
 */

import type { AlertSeverity, AnomalyAlertRead, AnomalyType, NodeTelemetry } from "../../types/api";

export interface DetectorSettings {
  /** Seconds between telemetry samples (used to project memory exhaustion and outage length). */
  telemetryIntervalSeconds: number;
  windowSize: number;
  minSamples: number;
  zscoreThreshold: number;
  cpuCriticalPercent: number;
  memoryLeakWindow: number;
  memoryLeakMinSlope: number;
  memoryLeakMinR2: number;
  bandwidthSaturationPercent: number;
  latencyCriticalMs: number;
  diskCriticalPercent: number;
  temperatureWarningC: number;
  temperatureCriticalC: number;
  serviceDownSamples: number;
  cooldownSeconds: number;
}

/** Defaults identical to backend/app/config.py. */
export const DEFAULT_DETECTOR_SETTINGS: Readonly<DetectorSettings> = {
  telemetryIntervalSeconds: 1,
  windowSize: 60,
  minSamples: 20,
  zscoreThreshold: 3,
  cpuCriticalPercent: 90,
  memoryLeakWindow: 90,
  memoryLeakMinSlope: 0.08,
  memoryLeakMinR2: 0.85,
  bandwidthSaturationPercent: 85,
  latencyCriticalMs: 250,
  diskCriticalPercent: 92,
  temperatureWarningC: 80,
  temperatureCriticalC: 90,
  serviceDownSamples: 3,
  cooldownSeconds: 60,
};

const EPSILON = 1e-9;
const RECOMPUTE_INTERVAL = 4096;

const METRIC_CPU = "cpu_percent";
const METRIC_MEMORY = "memory_percent";
const METRIC_DISK = "disk_percent";
const METRIC_LATENCY = "latency_ms";
const METRIC_NET_TOTAL = "net_total_kbps";
const METRIC_TEMPERATURE = "temperature_c";
const METRIC_OFFLINE_SAMPLES = "offline_samples";
const METRIC_NET_UTILISATION = "net_utilization_percent";

type TrackedMetric =
  | typeof METRIC_CPU
  | typeof METRIC_MEMORY
  | typeof METRIC_DISK
  | typeof METRIC_LATENCY
  | typeof METRIC_NET_TOTAL
  | typeof METRIC_TEMPERATURE;

export const TRACKED_METRICS: readonly TrackedMetric[] = [
  METRIC_CPU,
  METRIC_MEMORY,
  METRIC_DISK,
  METRIC_LATENCY,
  METRIC_NET_TOTAL,
  METRIC_TEMPERATURE,
];

/** Metrics whose anomalous samples are withheld from their baseline. */
const FROZEN_METRICS: ReadonlySet<TrackedMetric> = new Set<TrackedMetric>([
  METRIC_CPU,
  METRIC_DISK,
  METRIC_LATENCY,
  METRIC_NET_TOTAL,
  METRIC_TEMPERATURE,
]);

const CPU_SUSTAINED_SAMPLES = 3;
const CPU_MIN_ABSOLUTE_PERCENT = 50;
const CPU_MIN_RISE_POINTS = 10;
const CPU_CRITICAL_Z_FACTOR = 1.5;
const MEMORY_LEAK_MIN_POINTS = 30;
const MEMORY_LEAK_MIN_RISE_POINTS = 5;
const MEMORY_CRITICAL_PERCENT = 90;
const BANDWIDTH_CRITICAL_PERCENT = 95;
const BANDWIDTH_BURST_MIN_PERCENT = 50;
const LATENCY_MIN_ABSOLUTE_MS = 50;
const LATENCY_RELATIVE_FACTOR = 3;
const DISK_JUMP_MIN_PERCENT = 80;
const THERMAL_JUMP_MIN_C = 70;

const SEVERITY_RANK: Readonly<Record<AlertSeverity, number>> = { info: 0, warning: 1, critical: 2 };

// ---------------------------------------------------------------------------
// Numeric helpers
// ---------------------------------------------------------------------------

/**
 * Rolling mean / population variance over a fixed window in O(1) per push (Welford's algorithm
 * extended with sample removal). Floating point drift is removed by an exact recomputation every
 * RECOMPUTE_INTERVAL pushes.
 */
export class RollingStatistics {
  private readonly window: number;
  private readonly buffer: Float64Array;
  private head = 0;
  private size = 0;
  private meanValue = 0;
  private m2 = 0;
  private pushesSinceRecompute = 0;

  constructor(window: number) {
    if (window < 1) {
      throw new RangeError("window must be >= 1");
    }
    this.window = window;
    this.buffer = new Float64Array(window);
  }

  /** Add a sample, evicting the oldest one when the window is full. */
  push(value: number): void {
    if (this.size === this.window) {
      const oldest = this.buffer[this.head] ?? 0;
      this.size -= 1;
      this.remove(oldest);
    }
    this.buffer[(this.head + this.size) % this.window] = value;
    this.size += 1;
    const delta = value - this.meanValue;
    this.meanValue += delta / this.size;
    this.m2 += delta * (value - this.meanValue);
    this.pushesSinceRecompute += 1;
    if (this.pushesSinceRecompute >= RECOMPUTE_INTERVAL) {
      this.recompute();
    }
  }

  /** Remove `value` (already excluded from the size) from the running moments. */
  private remove(value: number): void {
    this.head = (this.head + 1) % this.window;
    const remaining = this.size;
    if (remaining === 0) {
      this.meanValue = 0;
      this.m2 = 0;
      return;
    }
    const previousMean = this.meanValue;
    const newMean = (previousMean * (remaining + 1) - value) / remaining;
    this.m2 -= (value - previousMean) * (value - newMean);
    this.meanValue = newMean;
    if (this.m2 < 0) {
      this.m2 = 0;
    }
  }

  private recompute(): void {
    this.pushesSinceRecompute = 0;
    if (this.size === 0) {
      this.meanValue = 0;
      this.m2 = 0;
      return;
    }
    const values = this.values();
    let sum = 0;
    for (const item of values) {
      sum += item;
    }
    this.meanValue = sum / this.size;
    let squares = 0;
    for (const item of values) {
      squares += (item - this.meanValue) ** 2;
    }
    this.m2 = squares;
  }

  get count(): number {
    return this.size;
  }

  get mean(): number {
    return this.size > 0 ? this.meanValue : 0;
  }

  get variance(): number {
    return this.size === 0 ? 0 : Math.max(this.m2, 0) / this.size;
  }

  /** Population standard deviation of the current window. */
  get std(): number {
    return Math.sqrt(this.variance);
  }

  /** Signed z-score of `value` against the window, or null when it is not meaningful. */
  zscore(value: number): number | null {
    if (this.size < 2) {
      return null;
    }
    const std = this.std;
    if (std < EPSILON) {
      return null;
    }
    return (value - this.meanValue) / std;
  }

  /** Snapshot of the window contents, oldest first. */
  values(): number[] {
    const out = new Array<number>(this.size);
    for (let index = 0; index < this.size; index += 1) {
      out[index] = this.buffer[(this.head + index) % this.window] ?? 0;
    }
    return out;
  }
}

/**
 * Ordinary least squares of `values` against their index. Returns `[slope per sample, r squared]`;
 * `[0, 0]` for fewer than two points or when the series has no variance.
 */
export function linearRegression(values: readonly number[]): [number, number] {
  const count = values.length;
  if (count < 2) {
    return [0, 0];
  }
  const xMean = (count - 1) / 2;
  let sum = 0;
  for (const value of values) {
    sum += value;
  }
  const yMean = sum / count;
  let sxx = 0;
  let sxy = 0;
  let syy = 0;
  for (let index = 0; index < count; index += 1) {
    const dx = index - xMean;
    const dy = (values[index] ?? 0) - yMean;
    sxx += dx * dx;
    sxy += dx * dy;
    syy += dy * dy;
  }
  if (sxx < EPSILON || syy < EPSILON) {
    return [0, 0];
  }
  const slope = sxy / sxx;
  const rSquared = (sxy * sxy) / (sxx * syy);
  return [slope, Math.min(Math.max(rSquared, 0), 1)];
}

/** Human readable duration used in outage and leak-projection messages ("45s", "12 min", "2.0 h"). */
export function formatDuration(seconds: number): string {
  if (seconds < 90) {
    return `${seconds.toFixed(0)}s`;
  }
  const minutes = seconds / 60;
  if (minutes < 90) {
    return `${minutes.toFixed(0)} min`;
  }
  const hours = minutes / 60;
  if (hours < 48) {
    return `${hours.toFixed(1)} h`;
  }
  return `${(hours / 24).toFixed(1)} days`;
}

function roundTo(value: number, digits: number): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function mean(values: readonly number[]): number {
  let sum = 0;
  for (const value of values) {
    sum += value;
  }
  return sum / values.length;
}

function populationStd(values: readonly number[]): number {
  const average = mean(values);
  let squares = 0;
  for (const value of values) {
    squares += (value - average) ** 2;
  }
  return Math.sqrt(squares / values.length);
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/** A metric value together with the baseline it was judged against (before the push). */
interface Observation {
  value: number;
  mean: number | null;
  std: number | null;
  z: number | null;
}

/** Baseline details of an alert message, e.g. " (limit 90%, baseline 38.2% ± 2.4, z=23.8)". */
export function formatClause(
  baseline: { mean: number | null; std: number | null; z: number | null },
  unit: string,
  leading: readonly string[] = [],
): string {
  const parts = [...leading];
  if (baseline.mean !== null && baseline.std !== null) {
    parts.push(`baseline ${baseline.mean.toFixed(1)}${unit} ± ${baseline.std.toFixed(1)}`);
  }
  if (baseline.z !== null) {
    parts.push(`z=${baseline.z.toFixed(1)}`);
  }
  return parts.length > 0 ? ` (${parts.join(", ")})` : "";
}

function scaled(observation: Observation, factor: number): Observation {
  return {
    value: observation.value * factor,
    mean: observation.mean === null ? null : observation.mean * factor,
    std: observation.std === null ? null : observation.std * factor,
    z: observation.z,
  };
}

/** Fixed-capacity FIFO of the most recent samples. */
class SlidingWindow {
  private readonly capacity: number;
  private readonly items: number[] = [];

  constructor(capacity: number) {
    this.capacity = capacity;
  }

  append(value: number): void {
    if (this.items.length === this.capacity) {
      this.items.shift();
    }
    this.items.push(value);
  }

  get length(): number {
    return this.items.length;
  }

  toArray(): number[] {
    return this.items.slice();
  }
}

interface NodeState {
  stats: Record<TrackedMetric, RollingStatistics>;
  memoryWindow: SlidingWindow;
  anomalousStreak: Partial<Record<TrackedMetric, number>>;
  cpuCriticalStreak: number;
  lastAlert: Partial<Record<AnomalyType, { at: number; severity: AlertSeverity }>>;
  offlineSamples: number;
  offlineSinceMs: number | null;
}

interface AlertDraft {
  anomalyType: AnomalyType;
  severity: AlertSeverity;
  metricName: string;
  observation: Observation;
  threshold: number;
  message: string;
}

export interface AnomalyDetectorOptions {
  settings?: Partial<DetectorSettings>;
  /** Allocates the id of every emitted alert (incremental). Defaults to an internal counter. */
  nextId?: () => number;
}

export interface BaselineSnapshotEntry {
  count: number;
  mean: number | null;
  std: number | null;
}

/** Stateful multi-metric anomaly detector keyed by node id. */
export class AnomalyDetector {
  private readonly settings: DetectorSettings;
  private readonly nextId: () => number;
  private readonly states = new Map<number, NodeState>();
  private readonly memoryMinPoints: number;
  private idCounter = 0;

  constructor(options: AnomalyDetectorOptions = {}) {
    this.settings = { ...DEFAULT_DETECTOR_SETTINGS, ...options.settings };
    this.nextId = options.nextId ?? (() => (this.idCounter += 1));
    this.memoryMinPoints = Math.min(this.settings.memoryLeakWindow, MEMORY_LEAK_MIN_POINTS);
  }

  // -- public API -------------------------------------------------------

  /** Update the node baseline with `sample` and return the alerts it triggers. */
  analyze(sample: NodeTelemetry): AnomalyAlertRead[] {
    const state = this.stateFor(sample.node_id);
    const atMs = Date.parse(sample.timestamp);
    if (sample.status === "offline") {
      return this.analyzeOffline(sample, state, atMs);
    }
    state.offlineSamples = 0;
    state.offlineSinceMs = null;
    const netTotal = sample.net_upload_kbps + sample.net_download_kbps;

    const cpu = this.observe(state, METRIC_CPU, sample.cpu_percent);
    const disk = this.observe(state, METRIC_DISK, sample.disk_percent);
    const net = this.observe(state, METRIC_NET_TOTAL, netTotal);
    const latency =
      sample.latency_ms !== null ? this.observe(state, METRIC_LATENCY, sample.latency_ms) : null;
    const temperature =
      sample.temperature_c !== null ? this.observe(state, METRIC_TEMPERATURE, sample.temperature_c) : null;

    state.memoryWindow.append(sample.memory_percent);
    state.stats[METRIC_MEMORY].push(sample.memory_percent);

    const candidates: (AlertDraft | null)[] = [
      this.evaluateCpu(sample, state, cpu),
      this.evaluateMemory(sample, state),
      this.evaluateBandwidth(sample, net),
      this.evaluateLatency(sample, latency),
      this.evaluateDisk(sample, disk),
      this.evaluateTemperature(sample, temperature),
    ];

    this.updateBaseline(state, METRIC_CPU, cpu);
    this.updateBaseline(state, METRIC_DISK, disk);
    this.updateBaseline(state, METRIC_NET_TOTAL, net);
    if (latency !== null) {
      this.updateBaseline(state, METRIC_LATENCY, latency);
    }
    if (temperature !== null) {
      this.updateBaseline(state, METRIC_TEMPERATURE, temperature);
    }

    return this.admitAll(sample, state, atMs, candidates);
  }

  /** Forget the baseline of one node, or of every node when `nodeId` is omitted. */
  reset(nodeId?: number): void {
    if (nodeId === undefined) {
      this.states.clear();
    } else {
      this.states.delete(nodeId);
    }
  }

  /** Per-metric `count` / `mean` / `std` of the current baseline window. */
  baselineSnapshot(nodeId: number): Record<string, BaselineSnapshotEntry> {
    const state = this.states.get(nodeId);
    const snapshot: Record<string, BaselineSnapshotEntry> = {};
    for (const metric of TRACKED_METRICS) {
      const stats = state?.stats[metric];
      if (stats === undefined || stats.count === 0) {
        snapshot[metric] = { count: 0, mean: null, std: null };
      } else {
        snapshot[metric] = { count: stats.count, mean: roundTo(stats.mean, 3), std: roundTo(stats.std, 3) };
      }
    }
    return snapshot;
  }

  // -- state management -------------------------------------------------

  private stateFor(nodeId: number): NodeState {
    let state = this.states.get(nodeId);
    if (state === undefined) {
      const window = this.settings.windowSize;
      state = {
        stats: {
          [METRIC_CPU]: new RollingStatistics(window),
          [METRIC_MEMORY]: new RollingStatistics(window),
          [METRIC_DISK]: new RollingStatistics(window),
          [METRIC_LATENCY]: new RollingStatistics(window),
          [METRIC_NET_TOTAL]: new RollingStatistics(window),
          [METRIC_TEMPERATURE]: new RollingStatistics(window),
        },
        memoryWindow: new SlidingWindow(this.settings.memoryLeakWindow),
        anomalousStreak: {},
        cpuCriticalStreak: 0,
        lastAlert: {},
        offlineSamples: 0,
        offlineSinceMs: null,
      };
      this.states.set(nodeId, state);
    }
    return state;
  }

  /** Judge `value` against the baseline as it is before `value` joins it. */
  private observe(state: NodeState, metric: TrackedMetric, value: number): Observation {
    const stats = state.stats[metric];
    const hasBaseline = stats.count >= 2;
    const z = stats.count >= this.settings.minSamples ? stats.zscore(value) : null;
    return {
      value,
      mean: hasBaseline ? stats.mean : null,
      std: hasBaseline ? stats.std : null,
      z,
    };
  }

  /** Push the value into the baseline unless it is part of an ongoing incident. */
  private updateBaseline(state: NodeState, metric: TrackedMetric, observation: Observation): void {
    const stats = state.stats[metric];
    if (!FROZEN_METRICS.has(metric)) {
      stats.push(observation.value);
      return;
    }
    const anomalous = observation.z !== null && observation.z >= this.settings.zscoreThreshold;
    if (!anomalous) {
      state.anomalousStreak[metric] = 0;
      stats.push(observation.value);
      return;
    }
    const streak = (state.anomalousStreak[metric] ?? 0) + 1;
    state.anomalousStreak[metric] = streak;
    if (streak > this.settings.windowSize) {
      // The "incident" outlived the window: accept it as the new normal.
      stats.push(observation.value);
    }
  }

  private analyzeOffline(sample: NodeTelemetry, state: NodeState, atMs: number): AnomalyAlertRead[] {
    state.offlineSamples += 1;
    if (state.offlineSinceMs === null) {
      state.offlineSinceMs = atMs;
    }
    return this.admitAll(sample, state, atMs, [this.evaluateServiceDown(sample, state, atMs)]);
  }

  /** Apply the cooldown to every candidate and materialise the ones that pass. */
  private admitAll(
    sample: NodeTelemetry,
    state: NodeState,
    atMs: number,
    candidates: readonly (AlertDraft | null)[],
  ): AnomalyAlertRead[] {
    const alerts: AnomalyAlertRead[] = [];
    for (const candidate of candidates) {
      if (candidate !== null && this.admit(state, candidate, atMs)) {
        alerts.push(this.build(sample, candidate));
      }
    }
    return alerts;
  }

  /** Per-(node, type) cooldown that still lets a higher severity through. */
  private admit(state: NodeState, draft: AlertDraft, atMs: number): boolean {
    const previous = state.lastAlert[draft.anomalyType];
    if (previous !== undefined) {
      const elapsedSeconds = (atMs - previous.at) / 1000;
      const inCooldown = elapsedSeconds < this.settings.cooldownSeconds;
      const escalated = SEVERITY_RANK[draft.severity] > SEVERITY_RANK[previous.severity];
      if (inCooldown && !escalated) {
        return false;
      }
    }
    state.lastAlert[draft.anomalyType] = { at: atMs, severity: draft.severity };
    return true;
  }

  // -- alert construction -----------------------------------------------

  private static clause(observation: Observation, unit: string, leading: readonly string[] = []): string {
    return formatClause(observation, unit, leading);
  }

  private build(sample: NodeTelemetry, draft: AlertDraft): AnomalyAlertRead {
    const { observation } = draft;
    return {
      id: this.nextId(),
      node_id: sample.node_id,
      detected_at: sample.timestamp,
      anomaly_type: draft.anomalyType,
      severity: draft.severity,
      metric_name: draft.metricName,
      observed_value: roundTo(observation.value, 2),
      baseline_mean: observation.mean === null ? null : roundTo(observation.mean, 3),
      baseline_std: observation.std === null ? null : roundTo(observation.std, 3),
      z_score: observation.z === null ? null : roundTo(observation.z, 3),
      threshold: roundTo(draft.threshold, 3),
      message: draft.message,
      acknowledged: false,
      acknowledged_at: null,
      node_hostname: sample.hostname,
    };
  }

  // -- per-anomaly evaluators --------------------------------------------

  private evaluateCpu(sample: NodeTelemetry, state: NodeState, observation: Observation): AlertDraft | null {
    const cfg = this.settings;
    const value = observation.value;
    const zThreshold = cfg.zscoreThreshold;
    const critical = cfg.cpuCriticalPercent;

    state.cpuCriticalStreak = value >= critical ? state.cpuCriticalStreak + 1 : 0;
    const sustained = state.cpuCriticalStreak >= CPU_SUSTAINED_SAMPLES;
    const statistical =
      observation.z !== null &&
      observation.mean !== null &&
      observation.z >= zThreshold &&
      value >= Math.max(observation.mean + CPU_MIN_RISE_POINTS, CPU_MIN_ABSOLUTE_PERCENT);
    if (!statistical && !sustained) {
      return null;
    }

    const isCritical =
      value >= critical || (observation.z !== null && observation.z >= zThreshold * CPU_CRITICAL_Z_FACTOR);
    const severity: AlertSeverity = isCritical ? "critical" : "warning";
    let message: string;
    let threshold: number;
    if (statistical) {
      message = `CPU spike on ${sample.hostname}: ${value.toFixed(1)}%${AnomalyDetector.clause(observation, "%")}`;
      threshold = zThreshold;
    } else {
      const lead = [`${state.cpuCriticalStreak} consecutive samples`, `limit ${critical.toFixed(0)}%`];
      message = `Sustained critical CPU load on ${sample.hostname}: ${value.toFixed(1)}%${AnomalyDetector.clause(observation, "%", lead)}`;
      threshold = critical;
    }
    return { anomalyType: "cpu_spike", severity, metricName: METRIC_CPU, observation, threshold, message };
  }

  private evaluateMemory(sample: NodeTelemetry, state: NodeState): AlertDraft | null {
    const cfg = this.settings;
    if (state.memoryWindow.length < this.memoryMinPoints) {
      return null;
    }
    const series = state.memoryWindow.toArray();
    const [slope, rSquared] = linearRegression(series);
    const first = series[0] ?? 0;
    const current = series[series.length - 1] ?? 0;
    if (
      slope < cfg.memoryLeakMinSlope ||
      rSquared < cfg.memoryLeakMinR2 ||
      current <= first + MEMORY_LEAK_MIN_RISE_POINTS
    ) {
      return null;
    }

    const secondsToExhaustion = (Math.max(100 - current, 0) / slope) * cfg.telemetryIntervalSeconds;
    const severity: AlertSeverity = current >= MEMORY_CRITICAL_PERCENT ? "critical" : "warning";
    const observation: Observation = {
      value: current,
      mean: mean(series),
      std: populationStd(series),
      z: null,
    };
    const message =
      `Possible memory leak on ${sample.hostname}: memory at ${current.toFixed(1)}%, ` +
      `growing ${slope.toFixed(3)} points/sample over the last ${series.length} samples ` +
      `(R²=${rSquared.toFixed(2)}), projected exhaustion in ~${formatDuration(secondsToExhaustion)}`;
    return {
      anomalyType: "memory_leak",
      severity,
      metricName: METRIC_MEMORY,
      observation,
      threshold: cfg.memoryLeakMinSlope,
      message,
    };
  }

  private evaluateBandwidth(sample: NodeTelemetry, totalObservation: Observation): AlertDraft | null {
    const cfg = this.settings;
    const capacityKbps = sample.link_capacity_mbps * 1000;
    const observation = scaled(totalObservation, 100 / capacityKbps);
    const utilisation = observation.value;
    const zThreshold = cfg.zscoreThreshold;
    const throughput = `${(totalObservation.value / 1000).toFixed(1)} Mbps of ${sample.link_capacity_mbps} Mbps`;

    if (utilisation >= cfg.bandwidthSaturationPercent) {
      const severity: AlertSeverity = utilisation >= BANDWIDTH_CRITICAL_PERCENT ? "critical" : "warning";
      const message = `Bandwidth saturation on ${sample.hostname}: link at ${utilisation.toFixed(1)}% (${throughput})${AnomalyDetector.clause(observation, "%")}`;
      return {
        anomalyType: "bandwidth_saturation",
        severity,
        metricName: METRIC_NET_UTILISATION,
        observation,
        threshold: cfg.bandwidthSaturationPercent,
        message,
      };
    }
    if (observation.z !== null && observation.z >= zThreshold && utilisation >= BANDWIDTH_BURST_MIN_PERCENT) {
      const message = `Network traffic burst on ${sample.hostname}: link at ${utilisation.toFixed(1)}% (${throughput})${AnomalyDetector.clause(observation, "%")}`;
      return {
        anomalyType: "bandwidth_saturation",
        severity: "warning",
        metricName: METRIC_NET_UTILISATION,
        observation,
        threshold: zThreshold,
        message,
      };
    }
    return null;
  }

  private evaluateLatency(sample: NodeTelemetry, observation: Observation | null): AlertDraft | null {
    if (observation === null) {
      return null;
    }
    const cfg = this.settings;
    const value = observation.value;

    if (value >= cfg.latencyCriticalMs) {
      const lead = [`limit ${cfg.latencyCriticalMs.toFixed(0)} ms`];
      const message = `Critical latency on ${sample.hostname}: ${value.toFixed(1)} ms${AnomalyDetector.clause(observation, " ms", lead)}`;
      return {
        anomalyType: "critical_latency",
        severity: "critical",
        metricName: METRIC_LATENCY,
        observation,
        threshold: cfg.latencyCriticalMs,
        message,
      };
    }
    if (
      observation.z !== null &&
      observation.mean !== null &&
      observation.z >= cfg.zscoreThreshold &&
      value >= Math.max(observation.mean * LATENCY_RELATIVE_FACTOR, LATENCY_MIN_ABSOLUTE_MS)
    ) {
      const message = `Latency spike on ${sample.hostname}: ${value.toFixed(1)} ms${AnomalyDetector.clause(observation, " ms")}`;
      return {
        anomalyType: "critical_latency",
        severity: "warning",
        metricName: METRIC_LATENCY,
        observation,
        threshold: cfg.zscoreThreshold,
        message,
      };
    }
    return null;
  }

  private evaluateServiceDown(sample: NodeTelemetry, state: NodeState, atMs: number): AlertDraft | null {
    const threshold = this.settings.serviceDownSamples;
    if (state.offlineSamples < threshold) {
      return null;
    }
    const sinceMs = state.offlineSinceMs ?? atMs;
    // The node was last seen alive one telemetry interval before its first offline sample.
    const downtime = (atMs - sinceMs) / 1000 + this.settings.telemetryIntervalSeconds;
    const observation: Observation = { value: state.offlineSamples, mean: null, std: null, z: null };
    const message =
      `Service down on ${sample.hostname}: node unreachable for ` +
      `${state.offlineSamples} consecutive samples (~${formatDuration(downtime)})`;
    return {
      anomalyType: "service_down",
      severity: "critical",
      metricName: METRIC_OFFLINE_SAMPLES,
      observation,
      threshold,
      message,
    };
  }

  private evaluateTemperature(sample: NodeTelemetry, observation: Observation | null): AlertDraft | null {
    if (observation === null) {
      return null;
    }
    const cfg = this.settings;
    const value = observation.value;

    if (value >= cfg.temperatureCriticalC) {
      const lead = [`limit ${cfg.temperatureCriticalC.toFixed(0)}°C`];
      const message = `Critical temperature on ${sample.hostname}: ${value.toFixed(1)}°C${AnomalyDetector.clause(observation, "°C", lead)}`;
      return {
        anomalyType: "thermal_spike",
        severity: "critical",
        metricName: METRIC_TEMPERATURE,
        observation,
        threshold: cfg.temperatureCriticalC,
        message,
      };
    }
    if (value >= cfg.temperatureWarningC) {
      const lead = [`limit ${cfg.temperatureWarningC.toFixed(0)}°C`];
      const message = `High temperature on ${sample.hostname}: ${value.toFixed(1)}°C${AnomalyDetector.clause(observation, "°C", lead)}`;
      return {
        anomalyType: "thermal_spike",
        severity: "warning",
        metricName: METRIC_TEMPERATURE,
        observation,
        threshold: cfg.temperatureWarningC,
        message,
      };
    }
    if (observation.z !== null && observation.z >= cfg.zscoreThreshold && value >= THERMAL_JUMP_MIN_C) {
      const message = `Sudden temperature rise on ${sample.hostname}: ${value.toFixed(1)}°C${AnomalyDetector.clause(observation, "°C")}`;
      return {
        anomalyType: "thermal_spike",
        severity: "warning",
        metricName: METRIC_TEMPERATURE,
        observation,
        threshold: cfg.zscoreThreshold,
        message,
      };
    }
    return null;
  }

  private evaluateDisk(sample: NodeTelemetry, observation: Observation): AlertDraft | null {
    const cfg = this.settings;
    const value = observation.value;

    if (value >= cfg.diskCriticalPercent) {
      const lead = [`limit ${cfg.diskCriticalPercent.toFixed(0)}%`];
      const message = `Disk pressure on ${sample.hostname}: ${value.toFixed(1)}% full${AnomalyDetector.clause(observation, "%", lead)}`;
      return {
        anomalyType: "disk_pressure",
        severity: "critical",
        metricName: METRIC_DISK,
        observation,
        threshold: cfg.diskCriticalPercent,
        message,
      };
    }
    if (observation.z !== null && observation.z >= cfg.zscoreThreshold && value >= DISK_JUMP_MIN_PERCENT) {
      const message = `Sudden disk usage jump on ${sample.hostname}: ${value.toFixed(1)}% full${AnomalyDetector.clause(observation, "%")}`;
      return {
        anomalyType: "disk_pressure",
        severity: "warning",
        metricName: METRIC_DISK,
        observation,
        threshold: cfg.zscoreThreshold,
        message,
      };
    }
    return null;
  }
}
