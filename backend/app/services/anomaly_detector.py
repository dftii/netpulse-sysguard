"""Statistical anomaly detection engine.

The detector keeps a bounded rolling baseline per node and per metric and combines
z-score analysis, absolute thresholds and a linear-regression trend test:

* CPU_SPIKE             - z-score outlier (with an absolute floor) or sustained critical load
* MEMORY_LEAK           - steady, strongly linear growth of memory utilisation
* BANDWIDTH_SATURATION  - link utilisation above a limit, or a traffic burst on a busy link
* CRITICAL_LATENCY      - absolute latency limit or a large relative jump
* DISK_PRESSURE         - absolute fill level or a sudden jump on an already full disk
* THERMAL_SPIKE         - absolute temperature limits or a sudden rise towards a hot operating point
* SERVICE_DOWN          - node unreachable (OFFLINE) for several consecutive samples

OFFLINE samples carry placeholder metrics, so they only feed the service-down counter: they
never reach a baseline and no other evaluator runs for them.

Z-scores are always computed against the baseline *before* the new sample is pushed into
it, so an anomaly never inflates its own baseline.  While a metric stays anomalous its
samples are withheld from the baseline ("baseline freezing"); once the anomalous state has
lasted longer than the window the samples are accepted again so the detector adapts to a
new normal.
"""

from __future__ import annotations

import logging
import math
import statistics
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.enums import AlertSeverity, AnomalyType, NodeStatus
from app.models import AnomalyAlert
from app.schemas import AnomalyAlertCreate, NodeTelemetry

logger = logging.getLogger(__name__)

_EPSILON = 1e-9
_RECOMPUTE_INTERVAL = 4096

METRIC_CPU = "cpu_percent"
METRIC_MEMORY = "memory_percent"
METRIC_DISK = "disk_percent"
METRIC_LATENCY = "latency_ms"
METRIC_NET_TOTAL = "net_total_kbps"
METRIC_TEMPERATURE = "temperature_c"
METRIC_OFFLINE_SAMPLES = "offline_samples"
TRACKED_METRICS: tuple[str, ...] = (
    METRIC_CPU,
    METRIC_MEMORY,
    METRIC_DISK,
    METRIC_LATENCY,
    METRIC_NET_TOTAL,
    METRIC_TEMPERATURE,
)
_FROZEN_METRICS: frozenset[str] = frozenset(
    {METRIC_CPU, METRIC_DISK, METRIC_LATENCY, METRIC_NET_TOTAL, METRIC_TEMPERATURE}
)

_CPU_SUSTAINED_SAMPLES = 3
_CPU_MIN_ABSOLUTE_PERCENT = 50.0
_CPU_MIN_RISE_POINTS = 10.0
_CPU_CRITICAL_Z_FACTOR = 1.5
_MEMORY_LEAK_MIN_POINTS = 30
_MEMORY_LEAK_MIN_RISE_POINTS = 5.0
_MEMORY_CRITICAL_PERCENT = 90.0
_BANDWIDTH_CRITICAL_PERCENT = 95.0
_BANDWIDTH_BURST_MIN_PERCENT = 50.0
_LATENCY_MIN_ABSOLUTE_MS = 50.0
_LATENCY_RELATIVE_FACTOR = 3.0
_DISK_JUMP_MIN_PERCENT = 80.0
_THERMAL_JUMP_MIN_C = 70.0

_SEVERITY_RANK: dict[AlertSeverity, int] = {
    AlertSeverity.INFO: 0,
    AlertSeverity.WARNING: 1,
    AlertSeverity.CRITICAL: 2,
}


# ---------------------------------------------------------------------------
# Numeric helpers
# ---------------------------------------------------------------------------


class RollingStatistics:
    """Rolling mean / population variance over a fixed window in O(1) per push.

    Uses Welford's algorithm extended with sample removal.  Accumulated floating point
    drift is eliminated by an exact recomputation every ``_RECOMPUTE_INTERVAL`` pushes
    (amortised cost stays constant).
    """

    def __init__(self, window: int) -> None:
        if window < 1:
            raise ValueError("window must be >= 1")
        self._window = window
        self._buffer: deque[float] = deque()
        self._mean = 0.0
        self._m2 = 0.0
        self._pushes_since_recompute = 0

    def push(self, value: float) -> None:
        """Add a sample, evicting the oldest one when the window is full."""
        if len(self._buffer) == self._window:
            self._remove(self._buffer.popleft())
        self._buffer.append(value)
        count = len(self._buffer)
        delta = value - self._mean
        self._mean += delta / count
        self._m2 += delta * (value - self._mean)

        self._pushes_since_recompute += 1
        if self._pushes_since_recompute >= _RECOMPUTE_INTERVAL:
            self._recompute()

    def _remove(self, value: float) -> None:
        """Remove ``value`` (already popped from the buffer) from the running moments."""
        remaining = len(self._buffer)
        if remaining == 0:
            self._mean = 0.0
            self._m2 = 0.0
            return
        previous_mean = self._mean
        new_mean = (previous_mean * (remaining + 1) - value) / remaining
        self._m2 -= (value - previous_mean) * (value - new_mean)
        self._mean = new_mean
        if self._m2 < 0.0:
            self._m2 = 0.0

    def _recompute(self) -> None:
        self._pushes_since_recompute = 0
        count = len(self._buffer)
        if count == 0:
            self._mean = 0.0
            self._m2 = 0.0
            return
        self._mean = math.fsum(self._buffer) / count
        self._m2 = math.fsum((item - self._mean) ** 2 for item in self._buffer)

    @property
    def count(self) -> int:
        return len(self._buffer)

    @property
    def mean(self) -> float:
        return self._mean if self._buffer else 0.0

    @property
    def variance(self) -> float:
        count = len(self._buffer)
        if count == 0:
            return 0.0
        return max(self._m2, 0.0) / count

    @property
    def std(self) -> float:
        """Population standard deviation of the current window."""
        return math.sqrt(self.variance)

    def zscore(self, value: float) -> float | None:
        """Signed z-score of ``value`` against the window, or None when it is not meaningful."""
        if len(self._buffer) < 2:
            return None
        std = self.std
        if std < _EPSILON:
            return None
        return (value - self._mean) / std

    def values(self) -> list[float]:
        """Snapshot of the window contents, oldest first."""
        return list(self._buffer)


def linear_regression(values: Sequence[float]) -> tuple[float, float]:
    """Ordinary least squares of ``values`` against their index.

    Returns ``(slope per sample, r_squared)``; ``(0.0, 0.0)`` for fewer than two points
    or when the series has no variance.
    """
    count = len(values)
    if count < 2:
        return 0.0, 0.0
    x_mean = (count - 1) / 2.0
    y_mean = math.fsum(values) / count
    sxx = 0.0
    sxy = 0.0
    syy = 0.0
    for index, value in enumerate(values):
        dx = index - x_mean
        dy = value - y_mean
        sxx += dx * dx
        sxy += dx * dy
        syy += dy * dy
    if sxx < _EPSILON or syy < _EPSILON:
        return 0.0, 0.0
    slope = sxy / sxx
    r_squared = (sxy * sxy) / (sxx * syy)
    return slope, min(max(r_squared, 0.0), 1.0)


def _format_duration(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    minutes = seconds / 60.0
    if minutes < 90:
        return f"{minutes:.0f} min"
    hours = minutes / 60.0
    if hours < 48:
        return f"{hours:.1f} h"
    return f"{hours / 24.0:.1f} days"


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Observation:
    """A metric value together with the baseline it was judged against (pre-push)."""

    value: float
    mean: float | None
    std: float | None
    z: float | None

    def scaled(self, factor: float) -> _Observation:
        """Express value/baseline in other units; the z-score is scale invariant."""
        return _Observation(
            value=self.value * factor,
            mean=None if self.mean is None else self.mean * factor,
            std=None if self.std is None else self.std * factor,
            z=self.z,
        )


@dataclass(slots=True)
class _NodeState:
    stats: dict[str, RollingStatistics]
    memory_window: deque[float]
    anomalous_streak: dict[str, int] = field(default_factory=dict)
    cpu_critical_streak: int = 0
    last_alert: dict[AnomalyType, tuple[datetime, AlertSeverity]] = field(default_factory=dict)
    offline_samples: int = 0
    offline_since: datetime | None = None


class AnomalyDetector:
    """Stateful multi-metric anomaly detector keyed by node id."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._states: dict[int, _NodeState] = {}
        self._memory_min_points = min(settings.anomaly_memory_leak_window, _MEMORY_LEAK_MIN_POINTS)

    # -- public API -------------------------------------------------------

    def analyze(self, sample: NodeTelemetry) -> list[AnomalyAlertCreate]:
        """Update the node baseline with ``sample`` and return the alerts it triggers."""
        state = self._state_for(sample.node_id)
        if sample.status is NodeStatus.OFFLINE:
            return self._analyze_offline(sample, state)
        state.offline_samples = 0
        state.offline_since = None
        net_total = sample.net_upload_kbps + sample.net_download_kbps

        observations: dict[str, _Observation] = {
            METRIC_CPU: self._observe(state, METRIC_CPU, sample.cpu_percent),
            METRIC_DISK: self._observe(state, METRIC_DISK, sample.disk_percent),
            METRIC_NET_TOTAL: self._observe(state, METRIC_NET_TOTAL, net_total),
        }
        if sample.latency_ms is not None:
            observations[METRIC_LATENCY] = self._observe(state, METRIC_LATENCY, sample.latency_ms)
        if sample.temperature_c is not None:
            observations[METRIC_TEMPERATURE] = self._observe(state, METRIC_TEMPERATURE, sample.temperature_c)

        state.memory_window.append(sample.memory_percent)
        state.stats[METRIC_MEMORY].push(sample.memory_percent)

        candidates: list[AnomalyAlertCreate | None] = [
            self._evaluate_cpu(sample, state, observations[METRIC_CPU]),
            self._evaluate_memory(sample, state),
            self._evaluate_bandwidth(sample, observations[METRIC_NET_TOTAL]),
            self._evaluate_latency(sample, observations.get(METRIC_LATENCY)),
            self._evaluate_disk(sample, observations[METRIC_DISK]),
            self._evaluate_temperature(sample, observations.get(METRIC_TEMPERATURE)),
        ]

        for metric, observation in observations.items():
            self._update_baseline(state, metric, observation)

        return self._admit_all(state, candidates)

    def _analyze_offline(self, sample: NodeTelemetry, state: _NodeState) -> list[AnomalyAlertCreate]:
        """Count consecutive unreachable samples; the placeholder metrics are never analysed."""
        state.offline_samples += 1
        if state.offline_since is None:
            state.offline_since = sample.timestamp
        return self._admit_all(state, [self._evaluate_service_down(sample, state)])

    def _admit_all(
        self, state: _NodeState, candidates: Sequence[AnomalyAlertCreate | None]
    ) -> list[AnomalyAlertCreate]:
        """Apply the cooldown to every candidate and return (and log) the ones that pass."""
        alerts: list[AnomalyAlertCreate] = []
        for candidate in candidates:
            if candidate is not None and self._admit(state, candidate):
                alerts.append(candidate)
                logger.warning(
                    "Anomaly detected [%s/%s] node_id=%d: %s",
                    candidate.anomaly_type.value,
                    candidate.severity.value,
                    candidate.node_id,
                    candidate.message,
                )
        return alerts

    async def analyze_and_persist(self, session: AsyncSession, samples: list[NodeTelemetry]) -> list[AnomalyAlert]:
        """Analyze every sample and store the resulting alerts in a single transaction."""
        created: list[AnomalyAlertCreate] = []
        for sample in samples:
            created.extend(self.analyze(sample))
        if not created:
            return []

        rows = [AnomalyAlert(**alert.model_dump()) for alert in created]
        session.add_all(rows)
        try:
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        for row in rows:
            await session.refresh(row)
        return rows

    def reset(self, node_id: int | None = None) -> None:
        """Forget the baseline of one node, or of every node when ``node_id`` is None."""
        if node_id is None:
            self._states.clear()
        else:
            self._states.pop(node_id, None)

    def baseline_snapshot(self, node_id: int) -> dict[str, dict[str, float | int | None]]:
        """Per-metric ``count`` / ``mean`` / ``std`` of the current baseline window."""
        state = self._states.get(node_id)
        snapshot: dict[str, dict[str, float | int | None]] = {}
        for metric in TRACKED_METRICS:
            stats = state.stats[metric] if state is not None else None
            if stats is None or stats.count == 0:
                snapshot[metric] = {"count": 0, "mean": None, "std": None}
            else:
                snapshot[metric] = {
                    "count": stats.count,
                    "mean": round(stats.mean, 3),
                    "std": round(stats.std, 3),
                }
        return snapshot

    # -- state management -------------------------------------------------

    def _state_for(self, node_id: int) -> _NodeState:
        state = self._states.get(node_id)
        if state is None:
            window = self._settings.anomaly_window_size
            state = _NodeState(
                stats={metric: RollingStatistics(window) for metric in TRACKED_METRICS},
                memory_window=deque(maxlen=self._settings.anomaly_memory_leak_window),
            )
            self._states[node_id] = state
        return state

    def _observe(self, state: _NodeState, metric: str, value: float) -> _Observation:
        """Judge ``value`` against the baseline as it is *before* ``value`` joins it."""
        stats = state.stats[metric]
        has_baseline = stats.count >= 2
        z = stats.zscore(value) if stats.count >= self._settings.anomaly_min_samples else None
        return _Observation(
            value=value,
            mean=stats.mean if has_baseline else None,
            std=stats.std if has_baseline else None,
            z=z,
        )

    def _update_baseline(self, state: _NodeState, metric: str, observation: _Observation) -> None:
        """Push the value into the baseline unless it is part of an ongoing incident."""
        stats = state.stats[metric]
        if metric not in _FROZEN_METRICS:
            stats.push(observation.value)
            return
        anomalous = observation.z is not None and observation.z >= self._settings.anomaly_zscore_threshold
        if not anomalous:
            state.anomalous_streak[metric] = 0
            stats.push(observation.value)
            return
        streak = state.anomalous_streak.get(metric, 0) + 1
        state.anomalous_streak[metric] = streak
        if streak > self._settings.anomaly_window_size:
            # The "incident" outlived the window: accept it as the new normal.
            stats.push(observation.value)

    def _admit(self, state: _NodeState, alert: AnomalyAlertCreate) -> bool:
        """Apply the per-(node, type) cooldown, allowing severity escalation."""
        previous = state.last_alert.get(alert.anomaly_type)
        if previous is not None:
            previous_time, previous_severity = previous
            elapsed = (alert.detected_at - previous_time).total_seconds()
            in_cooldown = elapsed < self._settings.anomaly_cooldown_seconds
            escalated = _SEVERITY_RANK[alert.severity] > _SEVERITY_RANK[previous_severity]
            if in_cooldown and not escalated:
                return False
        state.last_alert[alert.anomaly_type] = (alert.detected_at, alert.severity)
        return True

    # -- alert construction -----------------------------------------------

    @staticmethod
    def _clause(observation: _Observation, unit: str, leading: Sequence[str] = ()) -> str:
        parts = list(leading)
        if observation.mean is not None and observation.std is not None:
            parts.append(f"baseline {observation.mean:.1f}{unit} ± {observation.std:.1f}")
        if observation.z is not None:
            parts.append(f"z={observation.z:.1f}")
        return f" ({', '.join(parts)})" if parts else ""

    @staticmethod
    def _build(
        sample: NodeTelemetry,
        anomaly_type: AnomalyType,
        severity: AlertSeverity,
        metric_name: str,
        observation: _Observation,
        threshold: float,
        message: str,
    ) -> AnomalyAlertCreate:
        return AnomalyAlertCreate(
            node_id=sample.node_id,
            detected_at=sample.timestamp,
            anomaly_type=anomaly_type,
            severity=severity,
            metric_name=metric_name,
            observed_value=round(observation.value, 2),
            baseline_mean=None if observation.mean is None else round(observation.mean, 3),
            baseline_std=None if observation.std is None else round(observation.std, 3),
            z_score=None if observation.z is None else round(observation.z, 3),
            threshold=round(threshold, 3),
            message=message,
        )

    # -- per-anomaly evaluators --------------------------------------------

    def _evaluate_cpu(
        self, sample: NodeTelemetry, state: _NodeState, observation: _Observation
    ) -> AnomalyAlertCreate | None:
        cfg = self._settings
        value = observation.value
        z_threshold = cfg.anomaly_zscore_threshold
        critical = cfg.anomaly_cpu_critical_percent

        state.cpu_critical_streak = state.cpu_critical_streak + 1 if value >= critical else 0
        sustained = state.cpu_critical_streak >= _CPU_SUSTAINED_SAMPLES
        statistical = (
            observation.z is not None
            and observation.mean is not None
            and observation.z >= z_threshold
            and value >= max(observation.mean + _CPU_MIN_RISE_POINTS, _CPU_MIN_ABSOLUTE_PERCENT)
        )
        if not statistical and not sustained:
            return None

        is_critical = value >= critical or (
            observation.z is not None and observation.z >= z_threshold * _CPU_CRITICAL_Z_FACTOR
        )
        severity = AlertSeverity.CRITICAL if is_critical else AlertSeverity.WARNING
        if statistical:
            message = f"CPU spike on {sample.hostname}: {value:.1f}%{self._clause(observation, '%')}"
            threshold = z_threshold
        else:
            lead = [f"{state.cpu_critical_streak} consecutive samples", f"limit {critical:.0f}%"]
            message = f"Sustained critical CPU load on {sample.hostname}: {value:.1f}%{self._clause(observation, '%', lead)}"
            threshold = critical
        return self._build(
            sample, AnomalyType.CPU_SPIKE, severity, METRIC_CPU, observation, threshold, message
        )

    def _evaluate_memory(self, sample: NodeTelemetry, state: _NodeState) -> AnomalyAlertCreate | None:
        cfg = self._settings
        window = state.memory_window
        if len(window) < self._memory_min_points:
            return None
        series = list(window)
        slope, r_squared = linear_regression(series)
        if (
            slope < cfg.anomaly_memory_leak_min_slope
            or r_squared < cfg.anomaly_memory_leak_min_r2
            or series[-1] <= series[0] + _MEMORY_LEAK_MIN_RISE_POINTS
        ):
            return None

        current = series[-1]
        interval = cfg.telemetry_interval_seconds
        seconds_to_exhaustion = max(100.0 - current, 0.0) / slope * interval
        severity = AlertSeverity.CRITICAL if current >= _MEMORY_CRITICAL_PERCENT else AlertSeverity.WARNING
        observation = _Observation(
            value=current,
            mean=statistics.fmean(series),
            std=statistics.pstdev(series),
            z=None,
        )
        message = (
            f"Possible memory leak on {sample.hostname}: memory at {current:.1f}%, "
            f"growing {slope:.3f} points/sample over the last {len(series)} samples "
            f"(R²={r_squared:.2f}), projected exhaustion in ~{_format_duration(seconds_to_exhaustion)}"
        )
        return self._build(
            sample,
            AnomalyType.MEMORY_LEAK,
            severity,
            METRIC_MEMORY,
            observation,
            cfg.anomaly_memory_leak_min_slope,
            message,
        )

    def _evaluate_bandwidth(self, sample: NodeTelemetry, total_observation: _Observation) -> AnomalyAlertCreate | None:
        cfg = self._settings
        capacity_kbps = sample.link_capacity_mbps * 1000.0
        to_percent = 100.0 / capacity_kbps
        observation = total_observation.scaled(to_percent)
        utilisation = observation.value
        z_threshold = cfg.anomaly_zscore_threshold
        metric = "net_utilization_percent"
        throughput = f"{total_observation.value / 1000.0:.1f} Mbps of {sample.link_capacity_mbps:g} Mbps"

        if utilisation >= cfg.anomaly_bandwidth_saturation_percent:
            severity = (
                AlertSeverity.CRITICAL if utilisation >= _BANDWIDTH_CRITICAL_PERCENT else AlertSeverity.WARNING
            )
            message = (
                f"Bandwidth saturation on {sample.hostname}: link at {utilisation:.1f}% "
                f"({throughput}){self._clause(observation, '%')}"
            )
            return self._build(
                sample,
                AnomalyType.BANDWIDTH_SATURATION,
                severity,
                metric,
                observation,
                cfg.anomaly_bandwidth_saturation_percent,
                message,
            )
        if (
            observation.z is not None
            and observation.z >= z_threshold
            and utilisation >= _BANDWIDTH_BURST_MIN_PERCENT
        ):
            message = (
                f"Network traffic burst on {sample.hostname}: link at {utilisation:.1f}% "
                f"({throughput}){self._clause(observation, '%')}"
            )
            return self._build(
                sample,
                AnomalyType.BANDWIDTH_SATURATION,
                AlertSeverity.WARNING,
                metric,
                observation,
                z_threshold,
                message,
            )
        return None

    def _evaluate_latency(
        self, sample: NodeTelemetry, observation: _Observation | None
    ) -> AnomalyAlertCreate | None:
        if observation is None:
            return None
        cfg = self._settings
        value = observation.value
        z_threshold = cfg.anomaly_zscore_threshold

        if value >= cfg.anomaly_latency_critical_ms:
            lead = [f"limit {cfg.anomaly_latency_critical_ms:.0f} ms"]
            message = f"Critical latency on {sample.hostname}: {value:.1f} ms{self._clause(observation, ' ms', lead)}"
            return self._build(
                sample,
                AnomalyType.CRITICAL_LATENCY,
                AlertSeverity.CRITICAL,
                METRIC_LATENCY,
                observation,
                cfg.anomaly_latency_critical_ms,
                message,
            )
        if (
            observation.z is not None
            and observation.mean is not None
            and observation.z >= z_threshold
            and value >= max(observation.mean * _LATENCY_RELATIVE_FACTOR, _LATENCY_MIN_ABSOLUTE_MS)
        ):
            message = f"Latency spike on {sample.hostname}: {value:.1f} ms{self._clause(observation, ' ms')}"
            return self._build(
                sample,
                AnomalyType.CRITICAL_LATENCY,
                AlertSeverity.WARNING,
                METRIC_LATENCY,
                observation,
                z_threshold,
                message,
            )
        return None

    def _evaluate_service_down(self, sample: NodeTelemetry, state: _NodeState) -> AnomalyAlertCreate | None:
        threshold = self._settings.anomaly_service_down_samples
        if state.offline_samples < threshold:
            return None
        since = state.offline_since if state.offline_since is not None else sample.timestamp
        # The node was last seen alive one telemetry interval before its first offline sample.
        downtime = (sample.timestamp - since).total_seconds() + self._settings.telemetry_interval_seconds
        observation = _Observation(value=float(state.offline_samples), mean=None, std=None, z=None)
        message = (
            f"Service down on {sample.hostname}: node unreachable for "
            f"{state.offline_samples} consecutive samples (~{_format_duration(downtime)})"
        )
        return self._build(
            sample,
            AnomalyType.SERVICE_DOWN,
            AlertSeverity.CRITICAL,
            METRIC_OFFLINE_SAMPLES,
            observation,
            float(threshold),
            message,
        )

    def _evaluate_temperature(
        self, sample: NodeTelemetry, observation: _Observation | None
    ) -> AnomalyAlertCreate | None:
        if observation is None:
            return None
        cfg = self._settings
        value = observation.value
        z_threshold = cfg.anomaly_zscore_threshold

        if value >= cfg.anomaly_temperature_critical_c:
            lead = [f"limit {cfg.anomaly_temperature_critical_c:.0f}°C"]
            message = f"Critical temperature on {sample.hostname}: {value:.1f}°C{self._clause(observation, '°C', lead)}"
            return self._build(
                sample,
                AnomalyType.THERMAL_SPIKE,
                AlertSeverity.CRITICAL,
                METRIC_TEMPERATURE,
                observation,
                cfg.anomaly_temperature_critical_c,
                message,
            )
        if value >= cfg.anomaly_temperature_warning_c:
            lead = [f"limit {cfg.anomaly_temperature_warning_c:.0f}°C"]
            message = f"High temperature on {sample.hostname}: {value:.1f}°C{self._clause(observation, '°C', lead)}"
            return self._build(
                sample,
                AnomalyType.THERMAL_SPIKE,
                AlertSeverity.WARNING,
                METRIC_TEMPERATURE,
                observation,
                cfg.anomaly_temperature_warning_c,
                message,
            )
        if observation.z is not None and observation.z >= z_threshold and value >= _THERMAL_JUMP_MIN_C:
            message = f"Sudden temperature rise on {sample.hostname}: {value:.1f}°C{self._clause(observation, '°C')}"
            return self._build(
                sample,
                AnomalyType.THERMAL_SPIKE,
                AlertSeverity.WARNING,
                METRIC_TEMPERATURE,
                observation,
                z_threshold,
                message,
            )
        return None

    def _evaluate_disk(self, sample: NodeTelemetry, observation: _Observation) -> AnomalyAlertCreate | None:
        cfg = self._settings
        value = observation.value
        z_threshold = cfg.anomaly_zscore_threshold

        if value >= cfg.anomaly_disk_critical_percent:
            lead = [f"limit {cfg.anomaly_disk_critical_percent:.0f}%"]
            message = f"Disk pressure on {sample.hostname}: {value:.1f}% full{self._clause(observation, '%', lead)}"
            return self._build(
                sample,
                AnomalyType.DISK_PRESSURE,
                AlertSeverity.CRITICAL,
                METRIC_DISK,
                observation,
                cfg.anomaly_disk_critical_percent,
                message,
            )
        if observation.z is not None and observation.z >= z_threshold and value >= _DISK_JUMP_MIN_PERCENT:
            message = f"Sudden disk usage jump on {sample.hostname}: {value:.1f}% full{self._clause(observation, '%')}"
            return self._build(
                sample,
                AnomalyType.DISK_PRESSURE,
                AlertSeverity.WARNING,
                METRIC_DISK,
                observation,
                z_threshold,
                message,
            )
        return None
