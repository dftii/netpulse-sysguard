"""Demo-data seeder: 24 h of history for the eight enterprise nodes, alerts and port audits.

Run it from ``backend/`` next to ``run.py``::

    python seed.py              # add whatever is missing, never duplicate
    python seed.py --reset      # wipe the seeded nodes' history first, then reseed
    python seed.py --rng-seed 7 # different (but still reproducible) random history

What gets written
-----------------
* The eight enterprise nodes, taken from ``EnterpriseClusterSimulator(...).specs()`` and upserted
  by hostname with ``crud.upsert_nodes``. The running application upserts the very same
  hostnames at startup, so seeding before or after it never creates duplicates. The real host
  node is never touched.
* ``SAMPLES_PER_NODE`` (200) ``MetricSample`` rows per node spread over the last 24 hours (even
  spacing plus jitter, UTC). Values come from each simulator profile (baselines, diurnal curve,
  noise, occasional bursts) and include a few incident windows.
* ``AnomalyAlert`` rows generated *from those incident windows*: every alert points at the
  sample that triggered it, its observed value is that sample's value, and its baseline comes
  from the node's quiet samples. All ``AnomalyType`` values are covered, with mixed severities
  and a mix of acknowledged and open alerts. Alert semantics follow the live detector: link
  utilisation is the busiest direction over the capacity (full duplex), a CRITICAL CPU alert is
  a sustained critical load (three samples at or above the limit), and a statistical CPU outlier
  is a WARNING that persisted for ten consecutive samples.
* One ``PortAudit`` + ``PortFinding`` set per node, built as ``PortScanOutcome`` objects with the
  network scanner's own catalogue, classification (banner escalation included) and risk score,
  and saved with ``crud.save_port_audit``.

Idempotency rule
----------------
The decision is taken per node and per table (metrics, alerts, audits). A table is **skipped for
a node when that node already has history in it**, meaning at least one row older than
``HISTORY_GUARD`` (one hour) before the reference time. The one-hour margin matters: the live
application writes rows every few seconds, and those fresh rows must not stop the historical
backfill, while any previous seed run (whose rows span 24 h) always trips the guard. Every
seeded alert and audit is at least two hours old, so a second run inserts nothing.

``--reset`` deletes every metric, alert, audit and finding that belongs to the eight seeded
nodes (matched by ``node_id``) and then reseeds. Rows of any other node, notably the real host,
are never touched.

Transactions: the reset runs in one transaction; metrics and alerts of a node are written in one
transaction; each audit is saved by ``crud.save_port_audit`` (one commit per audit, and a node
has a single audit, so it is all-or-nothing as well).

Determinism: every node draws from its own ``random.Random`` seeded with ``rng_seed`` and the
hostname, so the same seed and reference time always give the same rows, whichever nodes are
skipped.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import math
import random
import statistics
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import InstrumentedAttribute

from app import crud
from app.config import Settings, get_settings
from app.database import Base, SessionLocal, dispose_db, init_db
from app.enums import AlertSeverity, AnomalyType, PortState
from app.models import AnomalyAlert, MetricSample, Node, PortAudit, PortFinding
from app.schemas import AnomalyAlertCreate, MetricValues, NodeCreate, PortFindingResult, PortScanOutcome
from app.services.anomaly_detector import (
    METRIC_CPU,
    METRIC_DISK,
    METRIC_LATENCY,
    METRIC_MEMORY,
    METRIC_NET_PEAK,
    METRIC_OFFLINE_SAMPLES,
    METRIC_TEMPERATURE,
    linear_regression,
)
from app.services.network_scanner import (
    COMMON_PORTS,
    NetworkScanner,
    calculate_risk_score,
    highest_risk,
    sanitize_banner,
)
from app.services.telemetry_collector import _PROFILES, EnterpriseClusterSimulator

if TYPE_CHECKING:
    from app.services.telemetry_collector import _NodeProfile

__all__ = [
    "AUDIT_PLANS",
    "DEFAULT_RNG_SEED",
    "HISTORY_GUARD",
    "INCIDENT_PLANS",
    "SAMPLES_PER_NODE",
    "WINDOW",
    "AuditPlan",
    "IncidentPlan",
    "SeedError",
    "SeedReport",
    "main",
    "seed_database",
]

logger = logging.getLogger("netpulse.seed")

SAMPLES_PER_NODE = 200
WINDOW = timedelta(hours=24)
HISTORY_GUARD = timedelta(hours=1)
DEFAULT_RNG_SEED = 1337

_JITTER_FRACTION = 0.25
_BURST_SAMPLE_RATE = 3.0  # one sample covers ~7 minutes, so bursts are likelier per sample than per tick

# Ceilings of normal (non-incident) operation, aligned with the live simulator.
_NORMAL_CPU_CEILING = 88.5
_NORMAL_MEMORY_CEILING = 88.0
_NORMAL_DISK_CEILING = 90.0
_NORMAL_NET_CEILING_FRACTION = 0.80  # per direction: links are full duplex and 85 % is the saturation limit
_NORMAL_LATENCY_CEILING_MS = 15.0

# Detector rules that decide alert shape and severity (kept in sync with app/services/anomaly_detector.py;
# tests/test_seed.py asserts the values still match).
_CPU_SUSTAINED_SAMPLES = 3  # consecutive samples at or above the critical CPU limit
_CPU_OUTLIER_PERSISTENCE_SAMPLES = 10  # consecutive statistical outliers before a WARNING is raised
_CPU_OUTLIER_MIN_PERCENT = 70.0
_CPU_OUTLIER_MIN_RISE_POINTS = 20.0
_CPU_WARNING_CEILING = 89.5  # a statistical outlier is only a WARNING, so it stays below the critical limit
_MEMORY_CRITICAL_PERCENT = 90.0
_BANDWIDTH_CRITICAL_PERCENT = 95.0
_METRIC_NET_UTILISATION = "net_utilization_percent"

_MEMORY_LEAK_PRE_SAMPLES = 4
_MEMORY_LEAK_WARNING_RISE = 10.0


class SeedError(RuntimeError):
    """Raised when the seed plan is inconsistent with the simulator's node catalogue."""


# ---------------------------------------------------------------------------
# Seed plans (what happened to which node, and when)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IncidentPlan:
    """One historical incident: shapes the metrics of a node and produces the matching alert(s).

    ``severity`` is the worst severity the incident reaches. Memory leaks and critical thermal
    events escalate and therefore produce a WARNING alert followed by a CRITICAL one. A CRITICAL
    CPU incident is the detector's sustained-critical-load alert (three consecutive samples at or
    above the critical limit); a WARNING one is a statistical outlier that persisted for ten
    consecutive samples. Bandwidth incidents drive the busiest link direction (the link is full
    duplex), not the sum of both.
    ``acknowledge_after_minutes`` is None for alerts that are still open.
    """

    hostname: str
    kind: AnomalyType
    severity: AlertSeverity
    hours_ago: float
    length: int
    acknowledge_after_minutes: int | None


INCIDENT_PLANS: tuple[IncidentPlan, ...] = (
    IncidentPlan("db-primary-01", AnomalyType.CPU_SPIKE, AlertSeverity.CRITICAL, 21.8, 3, 12),
    IncidentPlan("nas-storage-01", AnomalyType.DISK_PRESSURE, AlertSeverity.CRITICAL, 19.6, 4, 35),
    IncidentPlan("web-app-01", AnomalyType.CPU_SPIKE, AlertSeverity.WARNING, 17.4, 12, 8),
    IncidentPlan("lb-edge-01", AnomalyType.BANDWIDTH_SATURATION, AlertSeverity.CRITICAL, 14.3, 3, 22),
    IncidentPlan("cache-redis-01", AnomalyType.MEMORY_LEAK, AlertSeverity.CRITICAL, 13.0, 16, None),
    IncidentPlan("fw-core-01", AnomalyType.BANDWIDTH_SATURATION, AlertSeverity.WARNING, 11.2, 2, None),
    IncidentPlan("ai-gpu-node-01", AnomalyType.CPU_SPIKE, AlertSeverity.CRITICAL, 9.4, 5, 18),
    IncidentPlan("ai-gpu-node-01", AnomalyType.THERMAL_SPIKE, AlertSeverity.CRITICAL, 9.4, 5, 18),
    IncidentPlan("fw-core-01", AnomalyType.CRITICAL_LATENCY, AlertSeverity.WARNING, 8.3, 2, 15),
    IncidentPlan("dc-ad-01", AnomalyType.SERVICE_DOWN, AlertSeverity.CRITICAL, 7.1, 5, 6),
    IncidentPlan("web-app-01", AnomalyType.CRITICAL_LATENCY, AlertSeverity.CRITICAL, 5.3, 3, None),
    IncidentPlan("nas-storage-01", AnomalyType.THERMAL_SPIKE, AlertSeverity.WARNING, 4.2, 2, None),
    IncidentPlan("web-app-01", AnomalyType.SERVICE_DOWN, AlertSeverity.CRITICAL, 3.3, 4, None),
    IncidentPlan("dc-ad-01", AnomalyType.CPU_SPIKE, AlertSeverity.CRITICAL, 2.2, 3, None),
)

_ALLOWED_SEVERITIES: dict[AnomalyType, frozenset[AlertSeverity]] = {
    AnomalyType.CPU_SPIKE: frozenset({AlertSeverity.WARNING, AlertSeverity.CRITICAL}),
    AnomalyType.MEMORY_LEAK: frozenset({AlertSeverity.CRITICAL}),
    AnomalyType.BANDWIDTH_SATURATION: frozenset({AlertSeverity.WARNING, AlertSeverity.CRITICAL}),
    AnomalyType.CRITICAL_LATENCY: frozenset({AlertSeverity.WARNING, AlertSeverity.CRITICAL}),
    AnomalyType.DISK_PRESSURE: frozenset({AlertSeverity.CRITICAL}),
    AnomalyType.SERVICE_DOWN: frozenset({AlertSeverity.CRITICAL}),
    AnomalyType.THERMAL_SPIKE: frozenset({AlertSeverity.WARNING, AlertSeverity.CRITICAL}),
}

_MIN_INCIDENT_HOURS_AGO = 2.0
_MAX_INCIDENT_HOURS_AGO = 23.0
_MIN_LEAK_SAMPLES = 8
_MIN_CRITICAL_CPU_SAMPLES = _CPU_SUSTAINED_SAMPLES
_MIN_WARNING_CPU_SAMPLES = _CPU_OUTLIER_PERSISTENCE_SAMPLES
_MIN_ESCALATING_THERMAL_SAMPLES = 2


@dataclass(frozen=True, slots=True)
class AuditPlan:
    """A historical TCP audit: which ports were open (with raw banners) and when it ran."""

    hostname: str
    hours_ago: float
    open_ports: tuple[tuple[int, bytes | None], ...]


AUDIT_PLANS: tuple[AuditPlan, ...] = (
    AuditPlan(
        "fw-core-01",
        20.5,
        (
            (22, b"SSH-2.0-OpenSSH_9.6\r\n"),
            (23, b"\r\nFreeBSD/amd64 (fw-core-01) (ttyp0)\r\n\r\nlogin: "),
            (443, None),
        ),
    ),
    AuditPlan(
        "nas-storage-01",
        16.8,
        (
            (21, b"220 (vsFTPd 2.3.4)\r\n"),
            (22, b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n"),
            (139, None),
            (443, None),
            (445, None),
        ),
    ),
    AuditPlan(
        "ai-gpu-node-01",
        14.1,
        (
            (22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"),
            (443, None),
            (8000, b"HTTP/1.1 200 OK\r\nserver: uvicorn\r\n\r\n"),
        ),
    ),
    AuditPlan(
        "dc-ad-01",
        12.2,
        (
            (53, None),
            (88, None),
            (135, None),
            (389, None),
            (445, None),
            (636, None),
            (3389, None),
            (5985, None),
        ),
    ),
    AuditPlan(
        "cache-redis-01",
        9.9,
        (
            (22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"),
            (6379, None),
        ),
    ),
    AuditPlan(
        "web-app-01",
        5.2,
        (
            (22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"),
            (80, b"HTTP/1.1 301 Moved Permanently\r\nServer: nginx/1.24.0 (Ubuntu)\r\n\r\n"),
            (443, None),
        ),
    ),
    AuditPlan(
        "lb-edge-01",
        2.4,
        (
            (22, b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n"),
            (80, b"HTTP/1.1 301 Moved Permanently\r\ncontent-length: 0\r\n\r\n"),
            (443, None),
            (9090, b"HTTP/1.1 200 OK\r\nServer: HAProxy Stats\r\n\r\n"),
        ),
    ),
    AuditPlan(
        "db-primary-01",
        22.6,
        (
            (22, b"SSH-2.0-OpenSSH_7.4\r\n"),
            (5432, None),
        ),
    ),
)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SeedReport:
    """Outcome of one seeding run."""

    reset: bool
    window_start: datetime
    window_end: datetime
    nodes_total: int = 0
    nodes_created: int = 0
    deleted_metrics: int = 0
    deleted_alerts: int = 0
    deleted_audits: int = 0
    deleted_findings: int = 0
    metrics_inserted: int = 0
    alerts_inserted: int = 0
    audits_inserted: int = 0
    findings_inserted: int = 0
    skipped_metrics: list[str] = field(default_factory=list)
    skipped_alerts: list[str] = field(default_factory=list)
    skipped_audits: list[str] = field(default_factory=list)

    @property
    def total_inserted(self) -> int:
        """Rows written to metric_samples, anomaly_alerts, port_audits and port_findings."""
        return self.metrics_inserted + self.alerts_inserted + self.audits_inserted + self.findings_inserted

    def lines(self) -> list[str]:
        """Human readable multi-line summary."""
        lines = [
            f"Seed window  : {self.window_start:%Y-%m-%d %H:%M:%S} -> {self.window_end:%Y-%m-%d %H:%M:%S} UTC",
            f"Nodes        : {self.nodes_total} seeded nodes ({self.nodes_created} created)",
        ]
        if self.reset:
            lines.append(
                f"Reset        : deleted {self.deleted_metrics} metrics, {self.deleted_alerts} alerts, "
                f"{self.deleted_audits} audits, {self.deleted_findings} findings"
            )
        lines.extend(
            [
                f"Metrics      : {self.metrics_inserted} inserted, {len(self.skipped_metrics)} node(s) skipped",
                f"Alerts       : {self.alerts_inserted} inserted, {len(self.skipped_alerts)} node(s) skipped",
                f"Port audits  : {self.audits_inserted} inserted ({self.findings_inserted} findings), "
                f"{len(self.skipped_audits)} node(s) skipped",
            ]
        )
        if self.total_inserted == 0:
            lines.append("Nothing to do: the seeded nodes already have history (use --reset to rebuild it).")
        return lines


# ---------------------------------------------------------------------------
# Numeric helpers
# ---------------------------------------------------------------------------


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _diurnal(moment: datetime) -> float:
    """Daily load curve in [-1, 1] on the local wall clock, like the live simulator (peak 15:00)."""
    local = moment.astimezone()
    hour = local.hour + local.minute / 60.0 + local.second / 3600.0
    return math.sin(2.0 * math.pi * (hour - 9.0) / 24.0)


def _ar1(rng: random.Random, count: int, phi: float, sigma: float) -> list[float]:
    """Stationary AR(1) noise with innovation deviation ``sigma``."""
    value = rng.gauss(0.0, sigma / math.sqrt(1.0 - phi * phi))
    series: list[float] = []
    for _ in range(count):
        value = phi * value + rng.gauss(0.0, sigma)
        series.append(value)
    return series


@dataclass(frozen=True, slots=True)
class _Baseline:
    mean: float
    std: float

    def z(self, value: float) -> float | None:
        return (value - self.mean) / self.std if self.std > 1e-9 else None

    def scaled(self, factor: float) -> _Baseline:
        return _Baseline(self.mean * factor, self.std * factor)


def _baseline(values: Sequence[float]) -> _Baseline:
    return _Baseline(statistics.fmean(values), statistics.pstdev(values))


def _clause(baseline: _Baseline | None, z: float | None, unit: str, lead: Sequence[str] = ()) -> str:
    """Parenthesised context suffix, formatted exactly like the live detector's messages."""
    parts = list(lead)
    if baseline is not None:
        parts.append(f"baseline {baseline.mean:.1f}{unit} ± {baseline.std:.1f}")
    if z is not None:
        parts.append(f"z={z:.1f}")
    return f" ({', '.join(parts)})" if parts else ""


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = seconds / 60.0
    if minutes < 60:
        return f"{minutes:.0f} min"
    hours = minutes / 60.0
    if hours < 24:
        return f"{hours:.1f} h"
    return f"{hours / 24.0:.1f} days"


def _as_utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


# ---------------------------------------------------------------------------
# Per-node history builder
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _NodeHistory:
    samples: list[MetricSample]
    alerts: list[AnomalyAlert]


class _HistoryBuilder:
    """Generates the metric series of one node, applies its incidents and derives the alerts."""

    def __init__(
        self,
        profile: _NodeProfile,
        node_id: int,
        plans: Sequence[IncidentPlan],
        now: datetime,
        rng_seed: int,
        settings: Settings,
    ) -> None:
        self._profile = profile
        self._node_id = node_id
        self._plans = list(plans)
        self._now = now
        self._settings = settings
        self._rng = random.Random(f"{rng_seed}:{profile.hostname}")
        self._capacity_kbps = profile.link_capacity_mbps * 1000.0

        self._stamps = self._build_timestamps()
        count = len(self._stamps)
        self._offline: set[int] = set()
        self._temperature_override: dict[int, float] = {}
        self._windows: list[tuple[IncidentPlan, list[int]]] = []

        self._cpu: list[float] = []
        self._memory: list[float] = []
        self._disk: list[float] = []
        self._upload: list[float] = []
        self._download: list[float] = []
        self._latency: list[float | None] = []
        self._temperature: list[float | None] = []
        self._processes: list[int] = []
        self._temperature_noise = [self._rng.gauss(0.0, 0.4) for _ in range(count)]
        self._process_noise = [self._rng.gauss(0.0, 1.5) for _ in range(count)]
        self._baselines: dict[str, _Baseline] = {}

    # -- series generation -------------------------------------------------

    def _build_timestamps(self) -> list[datetime]:
        step = WINDOW / SAMPLES_PER_NODE
        start = self._now - WINDOW
        stamps: list[datetime] = []
        for index in range(SAMPLES_PER_NODE):
            centre = start + step * (index + 0.5)
            stamps.append(centre + step * self._rng.uniform(-_JITTER_FRACTION, _JITTER_FRACTION))
        return stamps

    def _generate_baseline_series(self) -> None:
        p = self._profile
        rng = self._rng
        count = len(self._stamps)
        diurnal = [_diurnal(stamp) for stamp in self._stamps]
        burst_probability = min(1.0, p.burst_probability * _BURST_SAMPLE_RATE)
        bursts = [rng.uniform(0.3, 1.0) if rng.random() < burst_probability else 0.0 for _ in range(count)]

        cpu_noise = _ar1(rng, count, 0.5, p.cpu_sigma * 1.5)
        memory_noise = _ar1(rng, count, 0.6, 0.5)
        upload_noise = _ar1(rng, count, 0.4, 0.08)
        download_noise = _ar1(rng, count, 0.4, 0.08)
        latency_noise = _ar1(rng, count, 0.4, p.base_latency_ms * 0.15)

        net_ceiling = self._capacity_kbps * _NORMAL_NET_CEILING_FRACTION
        for i, stamp in enumerate(self._stamps):
            self._cpu.append(
                _clamp(
                    p.base_cpu + p.cpu_diurnal * diurnal[i] + cpu_noise[i] + p.burst_magnitude * bursts[i],
                    1.0,
                    _NORMAL_CPU_CEILING,
                )
            )
            self._memory.append(_clamp(p.base_memory + 2.0 * diurnal[i] + memory_noise[i], 5.0, _NORMAL_MEMORY_CEILING))
            age_seconds = (self._now - stamp).total_seconds()
            self._disk.append(
                _clamp(p.base_disk - p.disk_growth_per_second * age_seconds + rng.gauss(0.0, 0.05), 1.0, _NORMAL_DISK_CEILING)
            )
            factor = 1.0 + p.net_diurnal * diurnal[i] + 0.5 * bursts[i]
            self._upload.append(
                _clamp(
                    self._capacity_kbps * p.base_upload_fraction * max(0.05, factor + upload_noise[i]),
                    0.0,
                    net_ceiling,
                )
            )
            self._download.append(
                _clamp(
                    self._capacity_kbps * p.base_download_fraction * max(0.05, factor + download_noise[i]),
                    0.0,
                    net_ceiling,
                )
            )
            self._latency.append(
                _clamp(
                    p.base_latency_ms + latency_noise[i] + abs(rng.gauss(0.0, p.base_latency_ms * 0.1)),
                    0.2,
                    _NORMAL_LATENCY_CEILING_MS,
                )
            )

        quiet_temperature = [self._thermal_model(cpu, noise) for cpu, noise in zip(self._cpu, self._temperature_noise, strict=True)]
        self._baselines = {
            METRIC_CPU: _baseline(self._cpu),
            METRIC_MEMORY: _baseline(self._memory),
            METRIC_DISK: _baseline(self._disk),
            METRIC_LATENCY: _baseline([value for value in self._latency if value is not None]),
            METRIC_NET_PEAK: _baseline([max(up, down) for up, down in zip(self._upload, self._download, strict=True)]),
            METRIC_TEMPERATURE: _baseline(quiet_temperature),
        }

    def _thermal_model(self, cpu: float, noise: float) -> float:
        return self._profile.temp_idle_c + self._profile.temp_load_c * cpu / 100.0 + noise

    # -- incidents -----------------------------------------------------------

    def _window_indices(self, plan: IncidentPlan) -> list[int]:
        onset = self._now - timedelta(hours=plan.hours_ago)
        start = next((i for i, stamp in enumerate(self._stamps) if stamp >= onset), None)
        if start is None:
            raise SeedError(f"Incident on {plan.hostname} starts after the last sample")
        return list(range(start, min(start + plan.length, len(self._stamps))))

    def _apply_incident(self, plan: IncidentPlan, indices: list[int]) -> None:
        rng = self._rng
        critical = plan.severity is AlertSeverity.CRITICAL
        kind = plan.kind
        if kind is AnomalyType.CPU_SPIKE:
            floor = self._cpu_outlier_floor()
            if not critical and floor + 0.5 > _CPU_WARNING_CEILING:
                raise SeedError(
                    f"{self._profile.hostname}: a statistical CPU outlier needs {floor:.1f}%, "
                    f"which is not a WARNING (limit {self._settings.anomaly_cpu_critical_percent:.0f}%)"
                )
            for i in indices:
                self._cpu[i] = (
                    rng.uniform(93.0, 99.0)
                    if critical
                    else min(_CPU_WARNING_CEILING, rng.uniform(floor + 0.5, floor + 4.0))
                )
        elif kind is AnomalyType.DISK_PRESSURE:
            for k, i in enumerate(indices):
                self._disk[i] = min(98.5, rng.uniform(93.2, 94.6) + 0.8 * k)
        elif kind is AnomalyType.BANDWIDTH_SATURATION:
            p = self._profile
            # Full duplex: the busiest direction (upload wins ties, like the detector) saturates the
            # link on its own and the other one follows its usual proportion.
            upload_is_busiest = p.base_upload_fraction >= p.base_download_fraction
            proportion = min(p.base_upload_fraction, p.base_download_fraction) / max(
                p.base_upload_fraction, p.base_download_fraction
            )
            for i in indices:
                utilisation = rng.uniform(0.955, 0.99) if critical else rng.uniform(0.87, 0.92)
                busiest = self._capacity_kbps * utilisation
                other = busiest * proportion * rng.uniform(0.85, 1.0)
                self._upload[i] = busiest if upload_is_busiest else other
                self._download[i] = other if upload_is_busiest else busiest
        elif kind is AnomalyType.CRITICAL_LATENCY:
            for i in indices:
                self._latency[i] = rng.uniform(280.0, 450.0) if critical else rng.uniform(62.0, 95.0)
        elif kind is AnomalyType.MEMORY_LEAK:
            start_value = self._pre_window_memory(indices[0])
            target = rng.uniform(95.5, 97.5)
            for k, i in enumerate(indices):
                progress = (k + 1) / len(indices)
                self._memory[i] = _clamp(start_value + (target - start_value) * progress + rng.gauss(0.0, 0.15), 0.0, 99.5)
        elif kind is AnomalyType.THERMAL_SPIKE:
            for k, i in enumerate(indices):
                hot = critical and k > 0
                self._temperature_override[i] = rng.uniform(91.0, 96.0) if hot else rng.uniform(81.0, 85.0)
        elif kind is AnomalyType.SERVICE_DOWN:
            self._offline.update(indices)

    def _cpu_outlier_floor(self) -> float:
        """Lowest CPU value that is a z-score outlier and also clears the detector's absolute and rise floors."""
        cpu = self._baselines[METRIC_CPU]
        z_floor = cpu.mean + (self._settings.anomaly_zscore_threshold + 0.3) * cpu.std
        return max(z_floor, cpu.mean + _CPU_OUTLIER_MIN_RISE_POINTS, _CPU_OUTLIER_MIN_PERCENT)

    def _is_cpu_outlier(self, value: float) -> bool:
        base = self._baselines[METRIC_CPU]
        z = base.z(value)
        return (
            z is not None
            and z >= self._settings.anomaly_zscore_threshold
            and value >= max(base.mean + _CPU_OUTLIER_MIN_RISE_POINTS, _CPU_OUTLIER_MIN_PERCENT)
        )

    def _pre_window_memory(self, start: int) -> float:
        before = self._memory[max(0, start - 3) : start]
        return statistics.fmean(before) if before else self._memory[start]

    def _finalise_series(self) -> None:
        p = self._profile
        for i in range(len(self._stamps)):
            if i in self._offline:
                self._cpu[i] = 0.0
                self._upload[i] = 0.0
                self._download[i] = 0.0
                self._latency[i] = None
                self._temperature.append(None)
                self._processes.append(0)
                continue
            self._temperature.append(
                self._temperature_override.get(i, self._thermal_model(self._cpu[i], self._temperature_noise[i]))
            )
            self._processes.append(max(1, round(p.base_processes + p.process_cpu_factor * self._cpu[i] + self._process_noise[i])))
        self._round_to_storage_precision()

    def _round_to_storage_precision(self) -> None:
        """Round every series to the precision the live pipeline stores, so alerts match their samples exactly."""
        self._cpu = [round(value, 2) for value in self._cpu]
        self._memory = [round(value, 3) for value in self._memory]
        self._disk = [round(value, 3) for value in self._disk]
        self._upload = [round(value, 1) for value in self._upload]
        self._download = [round(value, 1) for value in self._download]
        self._latency = [None if value is None else round(value, 2) for value in self._latency]
        self._temperature = [None if value is None else round(value, 1) for value in self._temperature]

    # -- samples -----------------------------------------------------------------

    def _build_samples(self) -> list[MetricSample]:
        total_mb = self._profile.memory_total_mb
        samples: list[MetricSample] = []
        for i, stamp in enumerate(self._stamps):
            latency = self._latency[i]
            temperature = self._temperature[i]
            values = MetricValues(
                cpu_percent=round(self._cpu[i], 2),
                memory_percent=round(self._memory[i], 3),
                memory_used_mb=round(total_mb * self._memory[i] / 100.0, 1),
                disk_percent=round(self._disk[i], 3),
                latency_ms=None if latency is None else round(latency, 2),
                net_upload_kbps=round(self._upload[i], 1),
                net_download_kbps=round(self._download[i], 1),
                process_count=self._processes[i],
                temperature_c=None if temperature is None else round(temperature, 1),
            )
            samples.append(MetricSample(node_id=self._node_id, timestamp=stamp, **values.model_dump()))
        return samples

    # -- alerts ---------------------------------------------------------------------

    def _require(self, metric: str, series: Sequence[float | None], index: int) -> float:
        value = series[index]
        if value is None:
            raise SeedError(f"{self._profile.hostname}: {metric} is missing at sample {index}")
        return value

    def _alert(
        self,
        plan: IncidentPlan,
        index: int,
        severity: AlertSeverity,
        metric: str,
        value: float,
        baseline: _Baseline | None,
        z: float | None,
        threshold: float,
        message: str,
    ) -> AnomalyAlert:
        detected_at = self._stamps[index]
        create = AnomalyAlertCreate(
            node_id=self._node_id,
            detected_at=detected_at,
            anomaly_type=plan.kind,
            severity=severity,
            metric_name=metric,
            observed_value=round(value, 2),
            baseline_mean=None if baseline is None else round(baseline.mean, 3),
            baseline_std=None if baseline is None else round(baseline.std, 3),
            z_score=None if z is None else round(z, 3),
            threshold=round(threshold, 3),
            message=message,
        )
        acknowledged = plan.acknowledge_after_minutes is not None
        acknowledged_at = (
            min(detected_at + timedelta(minutes=plan.acknowledge_after_minutes), self._now)
            if plan.acknowledge_after_minutes is not None
            else None
        )
        return AnomalyAlert(**create.model_dump(), acknowledged=acknowledged, acknowledged_at=acknowledged_at)

    def _alerts_for(self, plan: IncidentPlan, indices: list[int]) -> list[AnomalyAlert]:
        cfg = self._settings
        host = self._profile.hostname
        first = indices[0]
        kind = plan.kind

        if kind is AnomalyType.CPU_SPIKE:
            return self._cpu_alerts(plan, indices)

        if kind is AnomalyType.DISK_PRESSURE:
            base = self._baselines[METRIC_DISK]
            value = self._disk[first]
            limit = cfg.anomaly_disk_critical_percent
            message = f"Disk pressure on {host}: {value:.1f}% full{_clause(base, base.z(value), '%', [f'limit {limit:.0f}%'])}"
            return [self._alert(plan, first, AlertSeverity.CRITICAL, METRIC_DISK, value, base, base.z(value), limit, message)]

        if kind is AnomalyType.BANDWIDTH_SATURATION:
            upload, download = self._upload[first], self._download[first]
            peak = max(upload, download)
            direction = "upload" if upload >= download else "download"
            to_percent = 100.0 / self._capacity_kbps
            raw_base = self._baselines[METRIC_NET_PEAK]
            base = raw_base.scaled(to_percent)
            utilisation = peak * to_percent
            z = raw_base.z(peak)
            severity = AlertSeverity.CRITICAL if utilisation >= _BANDWIDTH_CRITICAL_PERCENT else AlertSeverity.WARNING
            throughput = f"{peak / 1000.0:.1f} Mbps {direction} of {self._profile.link_capacity_mbps:g} Mbps"
            message = f"Bandwidth saturation on {host}: link at {utilisation:.1f}% ({throughput}){_clause(base, z, '%')}"
            return [
                self._alert(
                    plan, first, severity, _METRIC_NET_UTILISATION, utilisation, base, z,
                    cfg.anomaly_bandwidth_saturation_percent, message,
                )
            ]

        if kind is AnomalyType.CRITICAL_LATENCY:
            base = self._baselines[METRIC_LATENCY]
            value = self._require(METRIC_LATENCY, self._latency, first)
            z = base.z(value)
            if plan.severity is AlertSeverity.CRITICAL:
                limit = cfg.anomaly_latency_critical_ms
                message = f"Critical latency on {host}: {value:.1f} ms{_clause(base, z, ' ms', [f'limit {limit:.0f} ms'])}"
                return [self._alert(plan, first, AlertSeverity.CRITICAL, METRIC_LATENCY, value, base, z, limit, message)]
            message = f"Latency spike on {host}: {value:.1f} ms{_clause(base, z, ' ms')}"
            return [
                self._alert(plan, first, AlertSeverity.WARNING, METRIC_LATENCY, value, base, z, cfg.anomaly_zscore_threshold, message)
            ]

        if kind is AnomalyType.MEMORY_LEAK:
            return self._memory_leak_alerts(plan, indices)

        if kind is AnomalyType.THERMAL_SPIKE:
            return self._thermal_alerts(plan, indices)

        # AnomalyType.SERVICE_DOWN
        required = cfg.anomaly_service_down_samples
        index = indices[required - 1]
        message = (
            f"Service down on {host}: node unreachable for {required} consecutive samples "
            f"(offline since {self._stamps[first]:%H:%M:%S} UTC)"
        )
        return [
            self._alert(plan, index, AlertSeverity.CRITICAL, METRIC_OFFLINE_SAMPLES, float(required), None, None, float(required), message)
        ]

    def _cpu_alerts(self, plan: IncidentPlan, indices: list[int]) -> list[AnomalyAlert]:
        """CRITICAL: sustained critical load; WARNING: a statistical outlier that persisted long enough."""
        cfg = self._settings
        host = self._profile.hostname
        base = self._baselines[METRIC_CPU]
        critical_limit = cfg.anomaly_cpu_critical_percent

        if plan.severity is AlertSeverity.CRITICAL:
            required = _CPU_SUSTAINED_SAMPLES
            window = indices[:required]
            if len(window) < required or any(self._cpu[i] < critical_limit for i in window):
                raise SeedError(f"{host}: critical CPU load is not sustained for {required} samples")
            index = window[-1]
            value = self._cpu[index]
            z = base.z(value)
            lead = [f"{required} consecutive samples", f"limit {critical_limit:.0f}%"]
            message = f"Sustained critical CPU load on {host}: {value:.1f}%{_clause(base, z, '%', lead)}"
            return [self._alert(plan, index, AlertSeverity.CRITICAL, METRIC_CPU, value, base, z, critical_limit, message)]

        required = _CPU_OUTLIER_PERSISTENCE_SAMPLES
        window = indices[:required]
        if len(window) < required or not all(self._is_cpu_outlier(self._cpu[i]) for i in window):
            raise SeedError(f"{host}: CPU outlier is not sustained for {required} samples")
        index = window[-1]
        value = self._cpu[index]
        if value >= critical_limit:
            raise SeedError(f"{host}: a statistical CPU outlier must stay below the {critical_limit:.0f}% critical limit")
        z = base.z(value)
        lead = [f"{required} consecutive samples above baseline"]
        message = f"CPU spike on {host}: {value:.1f}%{_clause(base, z, '%', lead)}"
        return [self._alert(plan, index, AlertSeverity.WARNING, METRIC_CPU, value, base, z, cfg.anomaly_zscore_threshold, message)]

    def _memory_leak_alerts(self, plan: IncidentPlan, indices: list[int]) -> list[AnomalyAlert]:
        cfg = self._settings
        host = self._profile.hostname
        start = indices[0]
        start_value = self._pre_window_memory(start)
        warning_index = next(i for i in indices if self._memory[i] >= start_value + _MEMORY_LEAK_WARNING_RISE)
        critical_index = next((i for i in indices if self._memory[i] >= _MEMORY_CRITICAL_PERCENT), None)
        if critical_index is None:
            raise SeedError(f"Memory leak on {host} never reaches {_MEMORY_CRITICAL_PERCENT:.0f}%")

        sample_seconds = (WINDOW / SAMPLES_PER_NODE).total_seconds()
        alerts: list[AnomalyAlert] = []
        for index in sorted({warning_index, critical_index}):
            series = self._memory[max(0, start - _MEMORY_LEAK_PRE_SAMPLES) : index + 1]
            slope, r_squared = linear_regression(series)
            current = series[-1]
            seconds_to_exhaustion = max(100.0 - current, 0.0) / slope * sample_seconds
            severity = AlertSeverity.CRITICAL if current >= _MEMORY_CRITICAL_PERCENT else AlertSeverity.WARNING
            message = (
                f"Possible memory leak on {host}: memory at {current:.1f}%, "
                f"growing {slope:.3f} points/sample over the last {len(series)} samples "
                f"(R²={r_squared:.2f}), projected exhaustion in ~{_format_duration(seconds_to_exhaustion)}"
            )
            alerts.append(
                self._alert(
                    plan, index, severity, METRIC_MEMORY, current, _baseline(series), None,
                    cfg.anomaly_memory_leak_min_slope, message,
                )
            )
        return alerts

    def _thermal_alerts(self, plan: IncidentPlan, indices: list[int]) -> list[AnomalyAlert]:
        cfg = self._settings
        host = self._profile.hostname
        base = self._baselines[METRIC_TEMPERATURE]
        warning_limit = cfg.anomaly_temperature_warning_c
        critical_limit = cfg.anomaly_temperature_critical_c

        chosen = [indices[0]]
        if plan.severity is AlertSeverity.CRITICAL:
            critical_index = next((i for i in indices if self._require(METRIC_TEMPERATURE, self._temperature, i) >= critical_limit), None)
            if critical_index is None:
                raise SeedError(f"Thermal incident on {host} never reaches {critical_limit:.0f}°C")
            chosen.append(critical_index)

        alerts: list[AnomalyAlert] = []
        for index in chosen:
            value = self._require(METRIC_TEMPERATURE, self._temperature, index)
            is_critical = value >= critical_limit
            limit = critical_limit if is_critical else warning_limit
            severity = AlertSeverity.CRITICAL if is_critical else AlertSeverity.WARNING
            z = base.z(value)
            title = "Critical temperature" if is_critical else "High temperature"
            message = f"{title} on {host}: {value:.1f}°C{_clause(base, z, '°C', [f'limit {limit:.0f}°C'])}"
            alerts.append(self._alert(plan, index, severity, METRIC_TEMPERATURE, value, base, z, limit, message))
        return alerts

    # -- entry point -----------------------------------------------------------------

    def build(self) -> _NodeHistory:
        self._generate_baseline_series()
        for plan in self._plans:
            indices = self._window_indices(plan)
            self._windows.append((plan, indices))
            self._apply_incident(plan, indices)
        self._finalise_series()

        alerts: list[AnomalyAlert] = []
        for plan, indices in self._windows:
            alerts.extend(self._alerts_for(plan, indices))
        alerts.sort(key=lambda alert: alert.detected_at)
        return _NodeHistory(samples=self._build_samples(), alerts=alerts)


# ---------------------------------------------------------------------------
# Port audits
# ---------------------------------------------------------------------------


def _build_audit(
    spec: NodeCreate,
    profile: _NodeProfile,
    plan: AuditPlan,
    scanner: NetworkScanner,
    now: datetime,
    rng_seed: int,
) -> PortScanOutcome:
    """Build the scan outcome with the scanner's own classification and scoring."""
    rng = random.Random(f"{rng_seed}:{spec.hostname}:audit")
    started_at = now - timedelta(hours=plan.hours_ago)
    duration_ms = round(rng.uniform(900.0, 2400.0), 2)
    host_latency_ms = round(profile.base_latency_ms * rng.uniform(1.0, 1.4) + rng.uniform(0.1, 0.4), 2)

    findings: list[PortFindingResult] = []
    for port, raw_banner in sorted(plan.open_ports):
        banner = sanitize_banner(raw_banner) if raw_banner else None
        classification = scanner.classify_port(port, banner)
        findings.append(
            PortFindingResult(
                port=port,
                service=classification.service,
                state=PortState.OPEN,
                banner=banner,
                response_ms=round(host_latency_ms + rng.uniform(0.05, 0.6), 2),
                risk_level=classification.risk_level,
                risk_reason=classification.risk_reason,
                recommendation=classification.recommendation,
            )
        )

    levels = [finding.risk_level for finding in findings]
    return PortScanOutcome(
        target_host=spec.ip_address,
        resolved_ip=spec.ip_address,
        started_at=started_at,
        finished_at=started_at + timedelta(milliseconds=duration_ms),
        duration_ms=duration_ms,
        host_reachable=True,
        host_latency_ms=host_latency_ms,
        total_ports_scanned=len(COMMON_PORTS),
        open_ports_count=len(findings),
        risk_score=calculate_risk_score(levels),
        overall_risk=highest_risk(levels),
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Database orchestration
# ---------------------------------------------------------------------------


def _validate_plans(profiles: dict[str, _NodeProfile], settings: Settings) -> None:
    """Fail fast when a plan references an unknown node or an impossible incident."""
    for incident in INCIDENT_PLANS:
        if incident.hostname not in profiles:
            raise SeedError(f"Incident plan references unknown node '{incident.hostname}'")
        if incident.severity not in _ALLOWED_SEVERITIES[incident.kind]:
            raise SeedError(f"{incident.kind.value} cannot be seeded with severity {incident.severity.value}")
        if not _MIN_INCIDENT_HOURS_AGO <= incident.hours_ago <= _MAX_INCIDENT_HOURS_AGO:
            raise SeedError(
                f"Incident on {incident.hostname} must start between {_MIN_INCIDENT_HOURS_AGO:g} and "
                f"{_MAX_INCIDENT_HOURS_AGO:g} hours ago"
            )
        minimum = {
            AnomalyType.CPU_SPIKE: _MIN_CRITICAL_CPU_SAMPLES
            if incident.severity is AlertSeverity.CRITICAL
            else _MIN_WARNING_CPU_SAMPLES,
            AnomalyType.SERVICE_DOWN: settings.anomaly_service_down_samples,
            AnomalyType.MEMORY_LEAK: _MIN_LEAK_SAMPLES,
            AnomalyType.THERMAL_SPIKE: _MIN_ESCALATING_THERMAL_SAMPLES
            if incident.severity is AlertSeverity.CRITICAL
            else 1,
        }.get(incident.kind, 1)
        if incident.length < minimum:
            raise SeedError(f"{incident.kind.value} incident on {incident.hostname} needs at least {minimum} samples")
    for audit in AUDIT_PLANS:
        if audit.hostname not in profiles:
            raise SeedError(f"Audit plan references unknown node '{audit.hostname}'")
        if audit.hours_ago < _MIN_INCIDENT_HOURS_AGO or not audit.open_ports:
            raise SeedError(f"Audit plan for {audit.hostname} must be older than 2 h and list open ports")


async def _ensure_schema(session_factory: async_sessionmaker[AsyncSession]) -> None:
    """Create the tables on the engine the session factory is bound to (the app engine by default)."""
    from app import models  # noqa: F401  (registers mappers on Base.metadata)

    bind = session_factory.kw.get("bind")
    if isinstance(bind, AsyncEngine):
        async with bind.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
    else:
        await init_db()


async def _has_history(
    session: AsyncSession,
    node_id: int,
    node_column: InstrumentedAttribute[int | None],
    moment_column: InstrumentedAttribute[datetime],
    cutoff: datetime,
) -> bool:
    """True when the node already owns a row older than ``cutoff`` in the given table."""
    found = await session.scalar(select(node_column).where(node_column == node_id, moment_column <= cutoff).limit(1))
    return found is not None


async def _delete_seeded_rows(session: AsyncSession, node_ids: Sequence[int], report: SeedReport) -> None:
    """Remove every metric, alert, audit and finding that belongs to the given nodes."""
    ids = list(node_ids)
    audit_ids = select(PortAudit.id).where(PortAudit.node_id.in_(ids))
    findings = await session.execute(delete(PortFinding).where(PortFinding.audit_id.in_(audit_ids)))
    audits = await session.execute(delete(PortAudit).where(PortAudit.node_id.in_(ids)))
    alerts = await session.execute(delete(AnomalyAlert).where(AnomalyAlert.node_id.in_(ids)))
    metrics = await session.execute(delete(MetricSample).where(MetricSample.node_id.in_(ids)))
    report.deleted_findings = int(findings.rowcount or 0)
    report.deleted_audits = int(audits.rowcount or 0)
    report.deleted_alerts = int(alerts.rowcount or 0)
    report.deleted_metrics = int(metrics.rowcount or 0)


async def seed_database(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    reset: bool = False,
    now: datetime | None = None,
    rng_seed: int = DEFAULT_RNG_SEED,
    settings: Settings | None = None,
) -> SeedReport:
    """Seed the eight enterprise nodes with 24 h of metrics, alerts and port audits.

    Args:
        session_factory: Sessions bound to the target database. Tables are created if missing.
        reset: Delete the seeded nodes' metrics, alerts and audits first, then reseed.
        now: Reference time (UTC); defaults to the current time. The history ends just before it.
        rng_seed: Seed of the deterministic random generators.
        settings: Settings used for the simulator catalogue and detector thresholds.

    Returns:
        A SeedReport with the inserted, skipped and deleted row counts.

    Raises:
        SeedError: the seed plan does not match the simulator's node catalogue.
    """
    settings = settings or get_settings()
    reference = _as_utc(now or datetime.now(UTC)).replace(microsecond=0)
    report = SeedReport(reset=reset, window_start=reference - WINDOW, window_end=reference)

    specs = EnterpriseClusterSimulator(settings).specs()
    profiles = {profile.hostname: profile for profile in _PROFILES}
    missing = [spec.hostname for spec in specs if spec.hostname not in profiles]
    if missing:
        raise SeedError(f"No simulator profile for node(s): {', '.join(missing)}")
    _validate_plans(profiles, settings)

    await _ensure_schema(session_factory)

    hostnames = [spec.hostname for spec in specs]
    async with session_factory() as session:
        existing = int(await session.scalar(select(func.count(Node.id)).where(Node.hostname.in_(hostnames))) or 0)
        node_ids = await crud.upsert_nodes(session, specs)
    report.nodes_total = len(specs)
    report.nodes_created = len(specs) - existing

    if reset:
        async with session_factory() as session, session.begin():
            await _delete_seeded_rows(session, [node_ids[hostname] for hostname in hostnames], report)

    cutoff = reference - HISTORY_GUARD
    scanner = NetworkScanner(settings)
    audit_plans = {plan.hostname: plan for plan in AUDIT_PLANS}

    for spec in specs:
        hostname = spec.hostname
        node_id = node_ids[hostname]
        node_plans = [plan for plan in INCIDENT_PLANS if plan.hostname == hostname]

        async with session_factory() as session, session.begin():
            skip_metrics = await _has_history(
                session, node_id, MetricSample.node_id, MetricSample.timestamp, cutoff
            )
            skip_alerts = await _has_history(
                session, node_id, AnomalyAlert.node_id, AnomalyAlert.detected_at, cutoff
            )
            if skip_metrics:
                report.skipped_metrics.append(hostname)
            if skip_alerts:
                report.skipped_alerts.append(hostname)
            if not (skip_metrics and skip_alerts):
                history = _HistoryBuilder(
                    profiles[hostname], node_id, node_plans, reference, rng_seed, settings
                ).build()
                if not skip_metrics:
                    session.add_all(history.samples)
                    report.metrics_inserted += len(history.samples)
                if not skip_alerts:
                    session.add_all(history.alerts)
                    report.alerts_inserted += len(history.alerts)

        audit_plan = audit_plans.get(hostname)
        if audit_plan is None:
            continue
        async with session_factory() as session:
            if await _has_history(session, node_id, PortAudit.node_id, PortAudit.started_at, cutoff):
                report.skipped_audits.append(hostname)
                continue
            outcome = _build_audit(spec, profiles[hostname], audit_plan, scanner, reference, rng_seed)
            await crud.save_port_audit(session, outcome, node_id)
            report.audits_inserted += 1
            report.findings_inserted += len(outcome.findings)

    logger.info(
        "Seed finished: %d metrics, %d alerts, %d audits, %d findings inserted",
        report.metrics_inserted,
        report.alerts_inserted,
        report.audits_inserted,
        report.findings_inserted,
    )
    return report


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed the NetPulse SysGuard database with 24 h of demo history (metrics, alerts, port audits)."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="delete the seeded nodes' metrics, alerts and audits first, then reseed (other nodes are untouched)",
    )
    parser.add_argument(
        "--rng-seed",
        type=int,
        default=DEFAULT_RNG_SEED,
        help=f"seed of the deterministic random generators (default: {DEFAULT_RNG_SEED})",
    )
    return parser.parse_args(argv)


async def _run(args: argparse.Namespace) -> SeedReport:
    try:
        return await seed_database(SessionLocal, reset=args.reset, rng_seed=args.rng_seed)
    finally:
        await dispose_db()


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code (0 on success, 1 on failure)."""
    args = _parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
    try:
        report = asyncio.run(_run(args))
    except Exception:  # noqa: BLE001 - report any failure with a non-zero exit code
        logger.exception("Seeding failed")
        return 1
    for line in report.lines():
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
