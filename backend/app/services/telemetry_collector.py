"""Telemetry collection: real host metrics (psutil) plus a simulated enterprise cluster.

The :class:`TelemetryCollector` is the single producer of :class:`~app.schemas.NodeTelemetry`
snapshots. It composes two sources:

* :class:`HostTelemetrySource` samples the machine the backend runs on using ``psutil``.
* :class:`EnterpriseClusterSimulator` generates believable metrics for eight enterprise nodes,
  including an incident engine (CPU spikes, memory leaks, bandwidth saturation, latency
  degradation, disk pressure, service outages and thermal spikes) that the anomaly detector
  can be exercised against.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import os
import platform
import random
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TypeVar

import psutil

from app.config import Settings
from app.enums import AnomalyType, NodeRole, NodeStatus
from app.schemas import NodeCreate, NodeTelemetry

__all__ = [
    "EnterpriseClusterSimulator",
    "HostTelemetrySource",
    "TelemetryCollector",
    "classify_status",
]

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

_BYTES_PER_MB = 1024.0 * 1024.0
_BYTES_PER_GB = 1024.0 * 1024.0 * 1024.0
_LATENCY_REFRESH_SECONDS = 2.0

# Status thresholds (any single metric crossing a threshold escalates the node).
_CRITICAL_CPU = 90.0
_CRITICAL_MEMORY = 92.0
_CRITICAL_DISK = 95.0
_CRITICAL_LATENCY_MS = 250.0
_WARNING_CPU = 75.0
_WARNING_MEMORY = 80.0
_WARNING_DISK = 85.0
_WARNING_LATENCY_MS = 120.0


def classify_status(
    cpu_percent: float,
    memory_percent: float,
    disk_percent: float,
    latency_ms: float | None,
) -> NodeStatus:
    """Derive a node health status from its headline metrics.

    CRITICAL when CPU >= 90, memory >= 92, disk >= 95 or latency >= 250 ms.
    WARNING when CPU >= 75, memory >= 80, disk >= 85 or latency >= 120 ms.
    Otherwise ONLINE. A missing latency measurement is treated as healthy.
    """
    latency = latency_ms if latency_ms is not None else 0.0
    if (
        cpu_percent >= _CRITICAL_CPU
        or memory_percent >= _CRITICAL_MEMORY
        or disk_percent >= _CRITICAL_DISK
        or latency >= _CRITICAL_LATENCY_MS
    ):
        return NodeStatus.CRITICAL
    if (
        cpu_percent >= _WARNING_CPU
        or memory_percent >= _WARNING_MEMORY
        or disk_percent >= _WARNING_DISK
        or latency >= _WARNING_LATENCY_MS
    ):
        return NodeStatus.WARNING
    return NodeStatus.ONLINE


def _clamp(value: float, low: float, high: float) -> float:
    """Restrict ``value`` to the closed interval [low, high]."""
    return max(low, min(high, value))


def _safe_call(func: Callable[[], _T], default: _T) -> _T:
    """Run ``func`` and return ``default`` if it raises, so one broken sensor never kills a tick."""
    try:
        return func()
    except Exception:  # noqa: BLE001 - psutil raises a wide family (Error, OSError, RuntimeError)
        logger.debug("Telemetry probe failed, using fallback", exc_info=True)
        return default


# ---------------------------------------------------------------------------
# Real host source
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _HostSample:
    """Raw metrics for the real host before they are wrapped in a NodeTelemetry."""

    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used_mb: float = 0.0
    disk_percent: float = 0.0
    net_upload_kbps: float = 0.0
    net_download_kbps: float = 0.0
    process_count: int = 0
    temperature_c: float | None = None
    uptime_seconds: float = 0.0


def _primary_ipv4() -> str:
    """Return the IPv4 address used for outbound traffic without sending any packet."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.5)
        sock.connect(("8.8.8.8", 80))  # UDP connect only selects a route; nothing is transmitted.
        address = str(sock.getsockname()[0])
        return address or "127.0.0.1"
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def _describe_os() -> str:
    """Return a human readable OS string, e.g. ``Windows 11 10.0.26200``."""
    system = platform.system()
    if system == "Linux":
        try:
            pretty = platform.freedesktop_os_release().get("PRETTY_NAME")
        except OSError:
            pretty = None
        if pretty:
            return pretty[:128]
    if system == "Darwin":
        return f"macOS {platform.mac_ver()[0]}".strip()[:128]
    parts = [part for part in (system, platform.release(), platform.version()) if part]
    return " ".join(parts)[:128] or "Unknown OS"


def _system_disk_path() -> str:
    """Path of the system volume whose usage represents the host disk."""
    if os.name == "nt":
        return os.environ.get("SystemDrive", "C:") + "\\"
    return "/"


class HostTelemetrySource:
    """Samples the machine hosting the backend using psutil.

    Blocking psutil calls run in a worker thread. Network round-trip latency is measured by a
    background task (refreshed at most every two seconds) so a slow probe never stalls a tick.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._hostname = socket.gethostname() or "localhost"
        self._disk_path = _system_disk_path()

        self._spec = self._build_spec()

        # Network rate state (bytes counters -> kbps).
        self._prev_net: tuple[int, int] | None = None
        self._prev_net_time: float = 0.0

        # Latency state.
        self._latency_ms: float | None = None
        self._latency_task: asyncio.Task[None] | None = None
        self._latency_started_at: float = -math.inf

        self._last_sample = _HostSample()

        # Prime psutil's CPU counter: the first call with interval=None always returns 0.0.
        _safe_call(lambda: psutil.cpu_percent(interval=None), 0.0)

    @property
    def hostname(self) -> str:
        return self._hostname

    @property
    def spec(self) -> NodeCreate:
        """Static description of the real host."""
        return self._spec

    def _build_spec(self) -> NodeCreate:
        cores = _safe_call(lambda: psutil.cpu_count(logical=True), None) or os.cpu_count() or 1
        memory_total_mb = _safe_call(lambda: psutil.virtual_memory().total / _BYTES_PER_MB, 0.0)
        disk_total_gb = _safe_call(
            lambda: psutil.disk_usage(self._disk_path).total / _BYTES_PER_GB, 0.0
        )
        return NodeCreate(
            hostname=self._hostname[:128],
            display_name=self._hostname[:128],
            role=NodeRole.HOST,
            ip_address=_safe_call(_primary_ipv4, "127.0.0.1"),
            os_name=_describe_os(),
            location="Local workstation",
            is_simulated=False,
            cpu_cores=max(1, int(cores)),
            memory_total_mb=round(max(memory_total_mb, 1.0), 1),
            disk_total_gb=round(max(disk_total_gb, 1.0), 1),
            link_capacity_mbps=self._detect_link_capacity(),
        )

    def _detect_link_capacity(self) -> float:
        """Highest reported speed (Mbps) among NICs that are up; configured default otherwise."""
        stats = _safe_call(psutil.net_if_stats, {})
        speeds = [float(nic.speed) for nic in stats.values() if nic.isup and nic.speed > 0]
        if speeds:
            return max(speeds)
        return float(self._settings.host_link_capacity_mbps)

    # -- latency ---------------------------------------------------------

    async def _probe_latency(self) -> float | None:
        """Measure one TCP connect round-trip (ms) to the configured probe endpoint."""
        host = self._settings.latency_probe_host
        port = self._settings.latency_probe_port
        timeout = self._settings.latency_probe_timeout_seconds
        writer: asyncio.StreamWriter | None = None
        started = time.perf_counter()
        try:
            async with asyncio.timeout(timeout):
                _reader, writer = await asyncio.open_connection(host, port)
            return (time.perf_counter() - started) * 1000.0
        except (OSError, TimeoutError):
            return None
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(OSError, TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)

    async def _refresh_latency(self) -> None:
        """Background task body: store the latest latency measurement (None on failure)."""
        try:
            self._latency_ms = await self._probe_latency()
        except Exception:  # noqa: BLE001 - a failed probe must never surface as a task error
            logger.debug("Latency probe crashed", exc_info=True)
            self._latency_ms = None

    def _schedule_latency_refresh(self) -> None:
        task = self._latency_task
        if task is not None and not task.done():
            return
        now = time.monotonic()
        if now - self._latency_started_at < _LATENCY_REFRESH_SECONDS:
            return
        self._latency_started_at = now
        self._latency_task = asyncio.create_task(self._refresh_latency(), name="host-latency-probe")

    # -- sampling --------------------------------------------------------

    def _read_temperature(self) -> float | None:
        reader = getattr(psutil, "sensors_temperatures", None)
        if reader is None:
            return None
        readings = _safe_call(reader, {})
        values = [
            float(entry.current)
            for entries in readings.values()
            for entry in entries
            if entry.current is not None
        ]
        return max(values) if values else None

    def _sample_blocking(self) -> _HostSample:
        """Collect every psutil metric. Runs in a worker thread."""
        last = self._last_sample

        cpu = _safe_call(lambda: psutil.cpu_percent(interval=None), last.cpu_percent)

        memory = _safe_call(psutil.virtual_memory, None)
        if memory is not None:
            memory_percent = float(memory.percent)
            memory_used_mb = max(0.0, (memory.total - memory.available) / _BYTES_PER_MB)
        else:
            memory_percent = last.memory_percent
            memory_used_mb = last.memory_used_mb

        disk = _safe_call(lambda: psutil.disk_usage(self._disk_path).percent, last.disk_percent)

        upload_kbps = 0.0
        download_kbps = 0.0
        counters = _safe_call(psutil.net_io_counters, None)
        now = time.monotonic()
        if counters is not None:
            sent, received = int(counters.bytes_sent), int(counters.bytes_recv)
            if self._prev_net is not None:
                elapsed = now - self._prev_net_time
                if elapsed > 0:
                    upload_kbps = max(0.0, (sent - self._prev_net[0]) * 8.0 / 1000.0 / elapsed)
                    download_kbps = max(0.0, (received - self._prev_net[1]) * 8.0 / 1000.0 / elapsed)
            self._prev_net = (sent, received)
            self._prev_net_time = now

        process_count = len(_safe_call(psutil.pids, []))
        if process_count == 0:
            process_count = last.process_count

        boot_time = _safe_call(psutil.boot_time, 0.0)
        uptime = max(0.0, time.time() - boot_time) if boot_time > 0 else last.uptime_seconds

        sample = _HostSample(
            cpu_percent=_clamp(float(cpu), 0.0, 100.0),
            memory_percent=_clamp(memory_percent, 0.0, 100.0),
            memory_used_mb=memory_used_mb,
            disk_percent=_clamp(float(disk), 0.0, 100.0),
            net_upload_kbps=upload_kbps,
            net_download_kbps=download_kbps,
            process_count=process_count,
            temperature_c=self._read_temperature(),
            uptime_seconds=uptime,
        )
        self._last_sample = sample
        return sample

    async def sample(self) -> tuple[_HostSample, float | None]:
        """Return the current host metrics and the last measured probe latency."""
        self._schedule_latency_refresh()
        try:
            sample = await asyncio.to_thread(self._sample_blocking)
        except Exception:  # noqa: BLE001 - never let the host source break the collection tick
            logger.warning("Host sampling failed; reusing the previous sample", exc_info=True)
            sample = self._last_sample
        return sample, self._latency_ms

    async def aclose(self) -> None:
        """Cancel the background latency probe."""
        task = self._latency_task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._latency_task = None


# ---------------------------------------------------------------------------
# Enterprise cluster simulator
# ---------------------------------------------------------------------------


def _diurnal_factor() -> float:
    """Daily load curve in [-1, 1] based on the wall clock; troughs at 03:00, peaks at 15:00."""
    now = datetime.now()
    hour = now.hour + now.minute / 60.0 + now.second / 3600.0
    return math.sin(2.0 * math.pi * (hour - 9.0) / 24.0)


@dataclass(frozen=True, slots=True)
class _NodeProfile:
    """Static specification and behavioural baseline of one simulated node."""

    hostname: str
    display_name: str
    role: NodeRole
    ip_address: str
    os_name: str
    location: str
    cpu_cores: int
    memory_total_mb: float
    disk_total_gb: float
    link_capacity_mbps: float
    base_cpu: float
    cpu_diurnal: float
    cpu_sigma: float
    base_memory: float
    base_disk: float
    disk_growth_per_second: float
    base_upload_fraction: float
    base_download_fraction: float
    net_diurnal: float
    base_latency_ms: float
    base_processes: int
    process_cpu_factor: float
    temp_idle_c: float
    temp_load_c: float
    burst_probability: float
    burst_magnitude: float

    @property
    def link_capacity_kbps(self) -> float:
        return self.link_capacity_mbps * 1000.0

    def to_spec(self) -> NodeCreate:
        return NodeCreate(
            hostname=self.hostname,
            display_name=self.display_name,
            role=self.role,
            ip_address=self.ip_address,
            os_name=self.os_name,
            location=self.location,
            is_simulated=True,
            cpu_cores=self.cpu_cores,
            memory_total_mb=self.memory_total_mb,
            disk_total_gb=self.disk_total_gb,
            link_capacity_mbps=self.link_capacity_mbps,
        )


_PROFILES: tuple[_NodeProfile, ...] = (
    _NodeProfile(
        hostname="db-primary-01",
        display_name="PostgreSQL Primary",
        role=NodeRole.DATABASE,
        ip_address="10.20.4.11",
        os_name="Ubuntu 22.04.4 LTS (PostgreSQL 16.2)",
        location="DC Madrid - Rack A3",
        cpu_cores=16,
        memory_total_mb=65536.0,
        disk_total_gb=2000.0,
        link_capacity_mbps=10000.0,
        base_cpu=38.0,
        cpu_diurnal=14.0,
        cpu_sigma=1.8,
        base_memory=68.0,
        base_disk=52.0,
        disk_growth_per_second=0.00005,
        base_upload_fraction=0.02,
        base_download_fraction=0.03,
        net_diurnal=0.35,
        base_latency_ms=1.2,
        base_processes=310,
        process_cpu_factor=0.6,
        temp_idle_c=40.0,
        temp_load_c=28.0,
        burst_probability=0.01,
        burst_magnitude=18.0,
    ),
    _NodeProfile(
        hostname="lb-edge-01",
        display_name="HAProxy Edge Balancer",
        role=NodeRole.LOAD_BALANCER,
        ip_address="10.20.1.10",
        os_name="Debian 12 (HAProxy 2.8)",
        location="DC Madrid - Rack A1",
        cpu_cores=8,
        memory_total_mb=16384.0,
        disk_total_gb=240.0,
        link_capacity_mbps=10000.0,
        base_cpu=24.0,
        cpu_diurnal=10.0,
        cpu_sigma=1.4,
        base_memory=36.0,
        base_disk=28.0,
        disk_growth_per_second=0.00001,
        base_upload_fraction=0.06,
        base_download_fraction=0.06,
        net_diurnal=0.4,
        base_latency_ms=0.4,
        base_processes=140,
        process_cpu_factor=0.3,
        temp_idle_c=38.0,
        temp_load_c=24.0,
        burst_probability=0.012,
        burst_magnitude=14.0,
    ),
    _NodeProfile(
        hostname="ai-gpu-node-01",
        display_name="AI GPU Compute Node",
        role=NodeRole.AI_COMPUTE,
        ip_address="10.20.3.40",
        os_name="Ubuntu 22.04.4 LTS (CUDA 12.4)",
        location="DC Madrid - Rack B2",
        cpu_cores=64,
        memory_total_mb=262144.0,
        disk_total_gb=7680.0,
        link_capacity_mbps=10000.0,
        base_cpu=58.0,
        cpu_diurnal=8.0,
        cpu_sigma=2.4,
        base_memory=72.0,
        base_disk=45.0,
        disk_growth_per_second=0.00004,
        base_upload_fraction=0.03,
        base_download_fraction=0.08,
        net_diurnal=0.3,
        base_latency_ms=2.5,
        base_processes=420,
        process_cpu_factor=0.9,
        temp_idle_c=52.0,
        temp_load_c=32.0,
        burst_probability=0.02,
        burst_magnitude=20.0,
    ),
    _NodeProfile(
        hostname="fw-core-01",
        display_name="pfSense Core Firewall",
        role=NodeRole.FIREWALL,
        ip_address="10.20.0.1",
        os_name="pfSense 2.7.2 (FreeBSD 14.0)",
        location="DC Madrid - Rack A1",
        cpu_cores=8,
        memory_total_mb=32768.0,
        disk_total_gb=480.0,
        link_capacity_mbps=10000.0,
        base_cpu=30.0,
        cpu_diurnal=12.0,
        cpu_sigma=1.6,
        base_memory=42.0,
        base_disk=22.0,
        disk_growth_per_second=0.00002,
        base_upload_fraction=0.22,
        base_download_fraction=0.24,
        net_diurnal=0.4,
        base_latency_ms=0.3,
        base_processes=95,
        process_cpu_factor=0.2,
        temp_idle_c=39.0,
        temp_load_c=26.0,
        burst_probability=0.012,
        burst_magnitude=16.0,
    ),
    _NodeProfile(
        hostname="web-app-01",
        display_name="Nginx Web Server",
        role=NodeRole.WEB_SERVER,
        ip_address="10.20.2.21",
        os_name="Ubuntu 22.04.4 LTS (nginx 1.24)",
        location="DC Madrid - Rack A4",
        cpu_cores=8,
        memory_total_mb=16384.0,
        disk_total_gb=500.0,
        link_capacity_mbps=1000.0,
        base_cpu=33.0,
        cpu_diurnal=15.0,
        cpu_sigma=1.7,
        base_memory=52.0,
        base_disk=41.0,
        disk_growth_per_second=0.00003,
        base_upload_fraction=0.18,
        base_download_fraction=0.06,
        net_diurnal=0.45,
        base_latency_ms=1.5,
        base_processes=180,
        process_cpu_factor=0.7,
        temp_idle_c=37.0,
        temp_load_c=25.0,
        burst_probability=0.015,
        burst_magnitude=16.0,
    ),
    _NodeProfile(
        hostname="cache-redis-01",
        display_name="Redis Cache",
        role=NodeRole.CACHE,
        ip_address="10.20.4.31",
        os_name="Ubuntu 22.04.4 LTS (Redis 7.2)",
        location="DC Madrid - Rack A3",
        cpu_cores=8,
        memory_total_mb=131072.0,
        disk_total_gb=480.0,
        link_capacity_mbps=10000.0,
        base_cpu=22.0,
        cpu_diurnal=9.0,
        cpu_sigma=1.2,
        base_memory=71.0,
        base_disk=18.0,
        disk_growth_per_second=0.00001,
        base_upload_fraction=0.05,
        base_download_fraction=0.05,
        net_diurnal=0.35,
        base_latency_ms=0.4,
        base_processes=90,
        process_cpu_factor=0.2,
        temp_idle_c=37.0,
        temp_load_c=22.0,
        burst_probability=0.01,
        burst_magnitude=12.0,
    ),
    _NodeProfile(
        hostname="nas-storage-01",
        display_name="TrueNAS Storage",
        role=NodeRole.STORAGE,
        ip_address="10.20.5.50",
        os_name="TrueNAS SCALE 24.04 (Debian 12)",
        location="DC Madrid - Rack C1",
        cpu_cores=12,
        memory_total_mb=65536.0,
        disk_total_gb=96000.0,
        link_capacity_mbps=10000.0,
        base_cpu=18.0,
        cpu_diurnal=7.0,
        cpu_sigma=1.1,
        base_memory=63.0,
        base_disk=74.0,
        disk_growth_per_second=0.00008,
        base_upload_fraction=0.10,
        base_download_fraction=0.08,
        net_diurnal=0.3,
        base_latency_ms=4.0,
        base_processes=240,
        process_cpu_factor=0.4,
        temp_idle_c=41.0,
        temp_load_c=20.0,
        burst_probability=0.01,
        burst_magnitude=14.0,
    ),
    _NodeProfile(
        hostname="dc-ad-01",
        display_name="Active Directory DC",
        role=NodeRole.DOMAIN_CONTROLLER,
        ip_address="10.20.6.5",
        os_name="Windows Server 2022 Datacenter 21H2",
        location="DC Madrid - Rack B1",
        cpu_cores=4,
        memory_total_mb=16384.0,
        disk_total_gb=256.0,
        link_capacity_mbps=1000.0,
        base_cpu=14.0,
        cpu_diurnal=6.0,
        cpu_sigma=1.0,
        base_memory=58.0,
        base_disk=44.0,
        disk_growth_per_second=0.00002,
        base_upload_fraction=0.02,
        base_download_fraction=0.02,
        net_diurnal=0.3,
        base_latency_ms=1.0,
        base_processes=120,
        process_cpu_factor=0.3,
        temp_idle_c=36.0,
        temp_load_c=20.0,
        burst_probability=0.008,
        burst_magnitude=10.0,
    ),
)

# Normal (non-incident) operation never exceeds these ceilings, so only incidents turn nodes critical.
_NORMAL_CPU_CEILING = 88.5
_NORMAL_MEMORY_CEILING = 88.0
_NORMAL_DISK_CEILING = 90.0
_NORMAL_NET_CEILING_FRACTION = 0.85
_NORMAL_LATENCY_CEILING_MS = 15.0
_NORMAL_TEMPERATURE_CEILING_C = 78.0  # stays below the 80 C anomaly warning threshold
_DISK_CLEANUP_THRESHOLD = 84.0
_DISK_CLEANUP_DROP = 6.0

# Thermal spike (cooling failure) incident: temperature target range, hard clamp and ramp speed.
_THERMAL_TARGET_RANGE_C = (91.0, 98.0)
_THERMAL_TARGET_JITTER_C = 0.3
_THERMAL_INCIDENT_MIN_C = 88.0
_THERMAL_INCIDENT_MAX_C = 105.0
_THERMAL_RISE_RATE = 0.6  # fraction of the gap to the target closed per tick
_THERMAL_NOISE_SCALE = 0.5  # sensor noise is damped while the heat sink is saturated
_TEMPERATURE_RELAX_RATE = 0.15  # fraction of the gap to the load-driven target closed per tick
_COOLING_CPU_RESIDUAL = 0.5  # CPU residual (points) above which load may legitimately run hot

# Per-tick decay of the post-incident residual for each metric (smooth recovery).
_RESIDUAL_DECAY: dict[str, float] = {
    "cpu": 0.80,
    "memory": 0.85,
    "disk": 0.94,
    "upload": 0.75,
    "download": 0.75,
    "latency": 0.60,
}


@dataclass(slots=True)
class _Incident:
    """An active simulated incident on one node."""

    kind: AnomalyType
    remaining: int
    target: float
    rate: float = 0.0
    value: float = 0.0


@dataclass(frozen=True, slots=True)
class _SimSample:
    """Metrics generated for one simulated node on one tick.

    While a SERVICE_DOWN incident is active the node is unreachable: ``latency_ms`` and
    ``temperature_c`` are ``None`` and every load metric is zero (``disk_percent`` keeps the
    last known level).
    """

    cpu_percent: float
    memory_percent: float
    disk_percent: float
    latency_ms: float | None
    net_upload_kbps: float
    net_download_kbps: float
    process_count: int
    temperature_c: float | None
    uptime_seconds: float
    incident: AnomalyType | None


@dataclass(slots=True)
class _SimNode:
    """Mutable state of one simulated node (noise processes, bursts, incident, residuals)."""

    profile: _NodeProfile
    rng: random.Random
    interval_seconds: float
    incident_probability: float
    boot_offset_seconds: float
    disk_level: float = 0.0
    last_disk_percent: float = 0.0
    temperature: float = 0.0
    cpu_noise: float = 0.0
    memory_noise: float = 0.0
    upload_noise: float = 0.0
    download_noise: float = 0.0
    latency_noise: float = 0.0
    process_noise: float = 0.0
    temperature_noise: float = 0.0
    burst_left: int = 0
    burst_total: int = 0
    burst_peak: float = 0.0
    incident: _Incident | None = None
    pending: tuple[AnomalyType, int] | None = None
    residual: dict[str, float] = field(default_factory=lambda: dict.fromkeys(_RESIDUAL_DECAY, 0.0))

    def __post_init__(self) -> None:
        self.disk_level = self.profile.base_disk
        self.last_disk_percent = self.profile.base_disk
        self.temperature = self.profile.temp_idle_c + self.profile.temp_load_c * (
            self.profile.base_cpu / 100.0
        )

    # -- helpers ---------------------------------------------------------

    def _ou(self, value: float, theta: float, sigma: float) -> float:
        """One Ornstein-Uhlenbeck step with long-run mean zero."""
        return value - theta * value + sigma * self.rng.gauss(0.0, 1.0)

    def _burst_envelope(self) -> float:
        """Smooth 0..1..0 envelope of an occasional short burst (0 when no burst is running)."""
        if self.burst_left <= 0:
            if self.rng.random() >= self.profile.burst_probability:
                return 0.0
            self.burst_total = self.rng.randint(4, 12)
            self.burst_left = self.burst_total
            self.burst_peak = self.rng.uniform(0.5, 1.0)
        progress = (self.burst_total - self.burst_left + 0.5) / self.burst_total
        self.burst_left -= 1
        return self.burst_peak * math.sin(math.pi * progress)

    def _start_incident(
        self, kind: AnomalyType, ticks: int, memory_now: float, disk_now: float
    ) -> None:
        rng = self.rng
        incident = _Incident(kind=kind, remaining=max(1, ticks), target=0.0)
        if kind is AnomalyType.CPU_SPIKE:
            incident.target = rng.uniform(93.0, 99.0)
        elif kind is AnomalyType.MEMORY_LEAK:
            incident.target = rng.uniform(95.5, 97.5)
            incident.rate = rng.uniform(0.4, 0.8)
            incident.value = memory_now
        elif kind is AnomalyType.BANDWIDTH_SATURATION:
            incident.target = rng.uniform(0.88, 0.99)
        elif kind is AnomalyType.CRITICAL_LATENCY:
            incident.target = rng.uniform(280.0, 700.0)
        elif kind is AnomalyType.DISK_PRESSURE:
            incident.target = rng.uniform(93.0, 98.0)
            incident.value = disk_now
            incident.rate = max(0.15, (incident.target - disk_now) / max(1.0, incident.remaining * 0.5))
        elif kind is AnomalyType.THERMAL_SPIKE:
            incident.target = rng.uniform(*_THERMAL_TARGET_RANGE_C)
            incident.value = self.temperature
        elif kind is AnomalyType.SERVICE_DOWN:
            incident.target = 0.0  # the node is unreachable: there is no metric to drive
        else:
            raise ValueError(f"Unsupported simulated incident kind: {kind!r}")
        self.incident = incident

    def _apply_incident(self, incident: _Incident) -> dict[str, float]:
        """Compute the forced metric values for this tick of an active incident.

        SERVICE_DOWN and THERMAL_SPIKE force no residual-tracked metric: an outage replaces the
        whole sample (see :meth:`_offline_sample`) and a thermal spike drives the temperature
        model directly (``incident.value`` holds this tick's temperature target).
        """
        rng = self.rng
        capacity_kbps = self.profile.link_capacity_kbps
        forced: dict[str, float] = {}
        if incident.kind is AnomalyType.CPU_SPIKE:
            forced["cpu"] = _clamp(incident.target + rng.uniform(-1.5, 1.5), 91.0, 100.0)
        elif incident.kind is AnomalyType.MEMORY_LEAK:
            incident.value = min(incident.target, incident.value + incident.rate)
            forced["memory"] = incident.value
        elif incident.kind is AnomalyType.BANDWIDTH_SATURATION:
            up = _clamp(incident.target + rng.uniform(-0.02, 0.02), 0.86, 0.995)
            down = _clamp(incident.target + rng.uniform(-0.02, 0.02), 0.86, 0.995)
            forced["upload"] = capacity_kbps * up
            forced["download"] = capacity_kbps * down
        elif incident.kind is AnomalyType.CRITICAL_LATENCY:
            forced["latency"] = _clamp(
                incident.target + rng.gauss(0.0, incident.target * 0.08), 280.0, 900.0
            )
        elif incident.kind is AnomalyType.DISK_PRESSURE:
            incident.value = min(incident.target, incident.value + incident.rate)
            forced["disk"] = incident.value
        elif incident.kind is AnomalyType.THERMAL_SPIKE:
            incident.value = _clamp(
                incident.target + rng.uniform(-_THERMAL_TARGET_JITTER_C, _THERMAL_TARGET_JITTER_C),
                _THERMAL_INCIDENT_MIN_C,
                _THERMAL_INCIDENT_MAX_C,
            )
        elif incident.kind is not AnomalyType.SERVICE_DOWN:
            raise ValueError(f"Unsupported simulated incident kind: {incident.kind!r}")
        return forced

    def _offline_sample(self, uptime_elapsed: float) -> _SimSample:
        """Sample of a node whose service is down (unreachable / crashed).

        Internal dynamics keep evolving (noise processes and disk growth already advanced in
        :meth:`step`, the chassis cools towards idle) but nothing is fed to the residual
        mechanism, so the node resumes its normal baseline right after the outage. The boot
        offset is re-anchored every offline tick, which makes uptime restart from zero.
        """
        for metric in self.residual:
            self.residual[metric] = 0.0
        self.temperature += _TEMPERATURE_RELAX_RATE * (self.profile.temp_idle_c - self.temperature)
        self.boot_offset_seconds = -uptime_elapsed
        return _SimSample(
            cpu_percent=0.0,
            memory_percent=0.0,
            disk_percent=round(self.last_disk_percent, 3),
            latency_ms=None,
            net_upload_kbps=0.0,
            net_download_kbps=0.0,
            process_count=0,
            temperature_c=None,
            uptime_seconds=0.0,
            incident=AnomalyType.SERVICE_DOWN,
        )

    def _next_temperature(self, cpu: float, thermal_target: float | None, cpu_forced: bool) -> float:
        """Advance the chassis temperature model one tick and return the sensor reading.

        A thermal spike pulls the temperature quickly towards its (cooling failure) target.
        Otherwise the temperature relaxes exponentially towards a load-driven target. Without an
        incident influencing the load, the target and the reading stay under
        ``_NORMAL_TEMPERATURE_CEILING_C``; a node cooling down after a spike or running hot
        because of a CPU incident is not clamped.
        """
        p = self.profile
        if thermal_target is not None:
            self.temperature += _THERMAL_RISE_RATE * (thermal_target - self.temperature)
            reading = self.temperature + _THERMAL_NOISE_SCALE * self.temperature_noise
            return min(reading, _THERMAL_INCIDENT_MAX_C)

        target = p.temp_idle_c + p.temp_load_c * cpu / 100.0
        load_is_normal = not cpu_forced and abs(self.residual["cpu"]) <= _COOLING_CPU_RESIDUAL
        if load_is_normal:
            target = min(target, _NORMAL_TEMPERATURE_CEILING_C)
        self.temperature += _TEMPERATURE_RELAX_RATE * (target - self.temperature)
        reading = self.temperature + self.temperature_noise
        if load_is_normal and self.temperature <= _NORMAL_TEMPERATURE_CEILING_C:
            reading = min(reading, _NORMAL_TEMPERATURE_CEILING_C)
        return reading

    # -- main step -------------------------------------------------------

    def step(self, diurnal: float, uptime_elapsed: float) -> _SimSample:
        """Advance the node by one tick and return its metrics."""
        p = self.profile
        rng = self.rng

        # Baseline dynamics: diurnal curve + mean-reverting noise + occasional bursts.
        self.cpu_noise = self._ou(self.cpu_noise, 0.15, p.cpu_sigma)
        self.memory_noise = self._ou(self.memory_noise, 0.05, 0.25)
        self.upload_noise = self._ou(self.upload_noise, 0.20, 0.06)
        self.download_noise = self._ou(self.download_noise, 0.20, 0.06)
        self.latency_noise = self._ou(self.latency_noise, 0.30, p.base_latency_ms * 0.08)
        self.process_noise = self._ou(self.process_noise, 0.10, 1.5)
        self.temperature_noise = self._ou(self.temperature_noise, 0.25, 0.3)
        burst = self._burst_envelope()

        self.disk_level += p.disk_growth_per_second * self.interval_seconds
        if self.disk_level > _DISK_CLEANUP_THRESHOLD:
            self.disk_level -= _DISK_CLEANUP_DROP  # log rotation / snapshot pruning

        capacity_kbps = p.link_capacity_kbps
        net_ceiling = capacity_kbps * _NORMAL_NET_CEILING_FRACTION
        net_factor_base = 1.0 + p.net_diurnal * diurnal + 0.5 * burst

        normal: dict[str, float] = {
            "cpu": _clamp(
                p.base_cpu + p.cpu_diurnal * diurnal + self.cpu_noise + p.burst_magnitude * burst,
                1.0,
                _NORMAL_CPU_CEILING,
            ),
            "memory": _clamp(
                p.base_memory + 2.0 * diurnal + self.memory_noise, 5.0, _NORMAL_MEMORY_CEILING
            ),
            "disk": _clamp(self.disk_level + rng.gauss(0.0, 0.01), 1.0, _NORMAL_DISK_CEILING),
            "upload": _clamp(
                capacity_kbps
                * p.base_upload_fraction
                * max(0.05, net_factor_base + self.upload_noise),
                0.0,
                net_ceiling,
            ),
            "download": _clamp(
                capacity_kbps
                * p.base_download_fraction
                * max(0.05, net_factor_base + self.download_noise),
                0.0,
                net_ceiling,
            ),
            "latency": _clamp(
                p.base_latency_ms
                + self.latency_noise
                + abs(rng.gauss(0.0, p.base_latency_ms * 0.1)),
                0.2,
                _NORMAL_LATENCY_CEILING_MS,
            ),
        }

        # Incident lifecycle: queued injection wins over random starts.
        if self.pending is not None:
            kind, ticks = self.pending
            self.pending = None
            self._start_incident(kind, ticks, normal["memory"], normal["disk"])
        elif (
            self.incident is None
            and self.incident_probability > 0.0
            and rng.random() < self.incident_probability
        ):
            self._start_incident(
                rng.choice(list(AnomalyType)),
                rng.randint(30, 120),
                normal["memory"],
                normal["disk"],
            )

        active_kind: AnomalyType | None = None
        forced: dict[str, float] = {}
        restart_service = False
        thermal_target: float | None = None
        if self.incident is not None:
            active_kind = self.incident.kind
            forced = self._apply_incident(self.incident)
            if active_kind is AnomalyType.THERMAL_SPIKE:
                thermal_target = self.incident.value
            self.incident.remaining -= 1
            if self.incident.remaining <= 0:
                restart_service = active_kind is AnomalyType.MEMORY_LEAK
                self.incident = None

        if active_kind is AnomalyType.SERVICE_DOWN:
            return self._offline_sample(uptime_elapsed)

        # Compose final values: during an incident the forced value wins; afterwards the
        # residual (forced - normal at the last incident tick) decays towards baseline.
        final: dict[str, float] = {}
        for metric, base_value in normal.items():
            if metric in forced:
                self.residual[metric] = forced[metric] - base_value
            else:
                self.residual[metric] *= _RESIDUAL_DECAY[metric]
                if abs(self.residual[metric]) < 1e-6:
                    self.residual[metric] = 0.0
            final[metric] = base_value + self.residual[metric]
        if restart_service:
            # The leaking service is "fixed" (restarted): memory drops to baseline on the next tick.
            self.residual["memory"] = 0.0

        cpu = _clamp(final["cpu"], 0.0, 100.0)
        memory = _clamp(final["memory"], 0.0, 100.0)
        disk = _clamp(final["disk"], 0.0, 100.0)
        upload = _clamp(final["upload"], 0.0, capacity_kbps)
        download = _clamp(final["download"], 0.0, capacity_kbps)
        latency = max(0.0, final["latency"])

        processes = max(1, round(p.base_processes + p.process_cpu_factor * cpu + self.process_noise))

        temperature = self._next_temperature(cpu, thermal_target, "cpu" in forced)
        self.last_disk_percent = disk

        return _SimSample(
            cpu_percent=round(cpu, 2),
            memory_percent=round(memory, 3),
            disk_percent=round(disk, 3),
            latency_ms=round(latency, 2),
            net_upload_kbps=round(upload, 1),
            net_download_kbps=round(download, 1),
            process_count=processes,
            temperature_c=round(temperature, 1),
            uptime_seconds=max(0.0, self.boot_offset_seconds + uptime_elapsed),
            incident=active_kind,
        )


class EnterpriseClusterSimulator:
    """Generates telemetry for eight simulated enterprise nodes with an incident engine."""

    def __init__(self, settings: Settings) -> None:
        self._interval = settings.telemetry_interval_seconds
        self._rng = random.Random(settings.simulator_seed)
        self._started = time.monotonic()
        self._nodes: dict[str, _SimNode] = {}
        for profile in _PROFILES:
            self._nodes[profile.hostname] = _SimNode(
                profile=profile,
                rng=self._rng,
                interval_seconds=self._interval,
                incident_probability=settings.simulator_incident_probability,
                boot_offset_seconds=self._rng.uniform(2.0, 120.0) * 86400.0,
            )

    @property
    def hostnames(self) -> list[str]:
        return list(self._nodes)

    def specs(self) -> list[NodeCreate]:
        return [node.profile.to_spec() for node in self._nodes.values()]

    def inject(self, hostname: str, anomaly_type: AnomalyType, duration_seconds: int) -> None:
        """Queue an incident that starts on the next tick and lasts ``duration_seconds``."""
        node = self._nodes[hostname]  # KeyError for unknown hostnames
        ticks = max(1, round(duration_seconds / self._interval))
        node.pending = (anomaly_type, ticks)

    def tick(self) -> dict[str, _SimSample]:
        """Advance every node by one tick."""
        diurnal = _diurnal_factor()
        elapsed = time.monotonic() - self._started
        return {name: node.step(diurnal, elapsed) for name, node in self._nodes.items()}


# ---------------------------------------------------------------------------
# Collector facade
# ---------------------------------------------------------------------------


class TelemetryCollector:
    """Produces one :class:`NodeTelemetry` snapshot per node on every collection tick."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._host = HostTelemetrySource(settings)
        self._simulator: EnterpriseClusterSimulator | None = (
            EnterpriseClusterSimulator(settings) if settings.enable_simulator else None
        )
        self._node_ids: dict[str, int] = {}
        self._specs: dict[str, NodeCreate] = {}
        for spec in self.node_specs():
            self._specs[spec.hostname] = spec

    @property
    def host_hostname(self) -> str:
        """Hostname of the real machine (the only non-simulated node)."""
        return self._host.hostname

    def simulated_hostnames(self) -> list[str]:
        return self._simulator.hostnames if self._simulator is not None else []

    def node_specs(self) -> list[NodeCreate]:
        """Static node descriptions: the real host first, then the simulated nodes."""
        specs = [self._host.spec.model_copy()]
        if self._simulator is not None:
            specs.extend(self._simulator.specs())
        return specs

    def bind_node_ids(self, mapping: dict[str, int]) -> None:
        """Register the hostname -> database id mapping produced by node seeding."""
        self._node_ids = dict(mapping)

    def inject_incident(
        self, hostname: str, anomaly_type: AnomalyType, duration_seconds: int
    ) -> None:
        """Force an incident on a simulated node.

        Raises:
            ValueError: the hostname is the real host (incidents are simulation only) or the
                duration is not positive.
            KeyError: the hostname does not belong to any simulated node.
        """
        if duration_seconds <= 0:
            raise ValueError("duration_seconds must be positive")
        if hostname == self._host.hostname:
            raise ValueError(f"'{hostname}' is the real host; incidents can only target simulated nodes")
        if self._simulator is None or hostname not in self._simulator.hostnames:
            raise KeyError(hostname)
        self._simulator.inject(hostname, anomaly_type, duration_seconds)

    async def collect(self) -> list[NodeTelemetry]:
        """Return a telemetry snapshot for every node (host first), sharing one timestamp."""
        if not self._node_ids:
            raise RuntimeError("TelemetryCollector.bind_node_ids() must be called before collect()")
        missing = [name for name in self._specs if name not in self._node_ids]
        if missing:
            raise RuntimeError(f"No database id bound for node(s): {', '.join(missing)}")

        timestamp = datetime.now(UTC)
        snapshots: list[NodeTelemetry] = []

        host_sample, host_latency = await self._host.sample()
        host_spec = self._host.spec
        snapshots.append(
            NodeTelemetry(
                node_id=self._node_ids[host_spec.hostname],
                hostname=host_spec.hostname,
                display_name=host_spec.display_name,
                role=host_spec.role,
                ip_address=host_spec.ip_address,
                is_simulated=False,
                status=classify_status(
                    host_sample.cpu_percent,
                    host_sample.memory_percent,
                    host_sample.disk_percent,
                    host_latency,
                ),
                timestamp=timestamp,
                cpu_percent=host_sample.cpu_percent,
                memory_percent=host_sample.memory_percent,
                memory_used_mb=host_sample.memory_used_mb,
                memory_total_mb=host_spec.memory_total_mb,
                disk_percent=host_sample.disk_percent,
                latency_ms=host_latency,
                net_upload_kbps=host_sample.net_upload_kbps,
                net_download_kbps=host_sample.net_download_kbps,
                process_count=host_sample.process_count,
                temperature_c=host_sample.temperature_c,
                link_capacity_mbps=host_spec.link_capacity_mbps,
                uptime_seconds=host_sample.uptime_seconds,
                simulated_incident=None,
            )
        )

        if self._simulator is not None:
            for hostname, sim in self._simulator.tick().items():
                spec = self._specs[hostname]
                if sim.incident is AnomalyType.SERVICE_DOWN:
                    status = NodeStatus.OFFLINE
                else:
                    status = classify_status(
                        sim.cpu_percent,
                        sim.memory_percent,
                        sim.disk_percent,
                        sim.latency_ms,
                    )
                snapshots.append(
                    NodeTelemetry(
                        node_id=self._node_ids[hostname],
                        hostname=hostname,
                        display_name=spec.display_name,
                        role=spec.role,
                        ip_address=spec.ip_address,
                        is_simulated=True,
                        status=status,
                        timestamp=timestamp,
                        cpu_percent=sim.cpu_percent,
                        memory_percent=sim.memory_percent,
                        memory_used_mb=round(spec.memory_total_mb * sim.memory_percent / 100.0, 1),
                        memory_total_mb=spec.memory_total_mb,
                        disk_percent=sim.disk_percent,
                        latency_ms=sim.latency_ms,
                        net_upload_kbps=sim.net_upload_kbps,
                        net_download_kbps=sim.net_download_kbps,
                        process_count=sim.process_count,
                        temperature_c=sim.temperature_c,
                        link_capacity_mbps=spec.link_capacity_mbps,
                        uptime_seconds=sim.uptime_seconds,
                        simulated_incident=sim.incident,
                    )
                )
        return snapshots

    async def aclose(self) -> None:
        """Release background resources (the host latency probe task)."""
        await self._host.aclose()
