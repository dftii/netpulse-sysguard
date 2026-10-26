"""Tests for the telemetry collector (real host source + enterprise cluster simulator)."""

from __future__ import annotations

import asyncio

import pytest

from app.config import Settings
from app.enums import AnomalyType, NodeRole, NodeStatus
from app.schemas import NodeTelemetry
from app.services import telemetry_collector as tc
from app.services.telemetry_collector import (
    HostTelemetrySource,
    TelemetryCollector,
    classify_status,
)

EXPECTED_SIMULATED = {
    "db-primary-01": NodeRole.DATABASE,
    "lb-edge-01": NodeRole.LOAD_BALANCER,
    "ai-gpu-node-01": NodeRole.AI_COMPUTE,
    "fw-core-01": NodeRole.FIREWALL,
    "web-app-01": NodeRole.WEB_SERVER,
    "cache-redis-01": NodeRole.CACHE,
    "nas-storage-01": NodeRole.STORAGE,
    "dc-ad-01": NodeRole.DOMAIN_CONTROLLER,
}


@pytest.fixture(autouse=True)
def _no_network_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the TCP latency probe so no test touches the network."""

    async def fake_probe(self: HostTelemetrySource) -> float | None:
        return 12.5

    monkeypatch.setattr(HostTelemetrySource, "_probe_latency", fake_probe)


@pytest.fixture
def constant_diurnal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Freeze the wall-clock dependent daily load curve for deterministic comparisons."""
    monkeypatch.setattr(tc, "_diurnal_factor", lambda: 0.0)


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "simulator_seed": 42,
        "simulator_incident_probability": 0.0,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def make_collector(**overrides: object) -> TelemetryCollector:
    collector = TelemetryCollector(make_settings(**overrides))
    collector.bind_node_ids({spec.hostname: index + 1 for index, spec in enumerate(collector.node_specs())})
    return collector


def by_host(snapshots: list[NodeTelemetry]) -> dict[str, NodeTelemetry]:
    return {snapshot.hostname: snapshot for snapshot in snapshots}


# ---------------------------------------------------------------------------
# classify_status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cpu", "mem", "disk", "latency", "expected"),
    [
        (10, 20, 30, 5, NodeStatus.ONLINE),
        (10, 20, 30, None, NodeStatus.ONLINE),
        (74.9, 79.9, 84.9, 119.9, NodeStatus.ONLINE),
        (75, 20, 30, 5, NodeStatus.WARNING),
        (10, 80, 30, 5, NodeStatus.WARNING),
        (10, 20, 85, 5, NodeStatus.WARNING),
        (10, 20, 30, 120, NodeStatus.WARNING),
        (89.9, 91.9, 94.9, 249.9, NodeStatus.WARNING),
        (90, 20, 30, 5, NodeStatus.CRITICAL),
        (10, 92, 30, 5, NodeStatus.CRITICAL),
        (10, 20, 95, 5, NodeStatus.CRITICAL),
        (10, 20, 30, 250, NodeStatus.CRITICAL),
        (95, 85, 90, 130, NodeStatus.CRITICAL),
    ],
)
def test_classify_status_thresholds(
    cpu: float, mem: float, disk: float, latency: float | None, expected: NodeStatus
) -> None:
    assert classify_status(cpu, mem, disk, latency) is expected


# ---------------------------------------------------------------------------
# Node specs and binding
# ---------------------------------------------------------------------------


def test_node_specs_with_simulator() -> None:
    collector = TelemetryCollector(make_settings())
    specs = collector.node_specs()
    hostnames = [spec.hostname for spec in specs]

    assert len(specs) == 9
    assert len(set(hostnames)) == 9
    assert specs[0].hostname == collector.host_hostname
    assert specs[0].role is NodeRole.HOST
    assert specs[0].is_simulated is False
    assert specs[0].location == "Local workstation"
    assert hostnames[1:] == collector.simulated_hostnames()
    assert {spec.hostname: spec.role for spec in specs[1:]} == EXPECTED_SIMULATED
    assert all(spec.is_simulated for spec in specs[1:])
    assert all(spec.ip_address.startswith("10.20.") for spec in specs[1:])


def test_node_specs_without_simulator() -> None:
    collector = TelemetryCollector(make_settings(enable_simulator=False))
    specs = collector.node_specs()

    assert len(specs) == 1
    assert specs[0].hostname == collector.host_hostname
    assert collector.simulated_hostnames() == []


def test_simulated_specs_are_heterogeneous() -> None:
    specs = {spec.hostname: spec for spec in TelemetryCollector(make_settings()).node_specs()}

    assert specs["ai-gpu-node-01"].cpu_cores > specs["dc-ad-01"].cpu_cores
    assert specs["ai-gpu-node-01"].memory_total_mb > specs["web-app-01"].memory_total_mb
    assert specs["nas-storage-01"].disk_total_gb > specs["db-primary-01"].disk_total_gb
    assert {spec.link_capacity_mbps for spec in specs.values() if spec.is_simulated} == {1000.0, 10000.0}


@pytest.mark.asyncio
async def test_collect_before_bind_raises() -> None:
    collector = TelemetryCollector(make_settings())
    with pytest.raises(RuntimeError):
        await collector.collect()


@pytest.mark.asyncio
async def test_collect_with_incomplete_binding_raises() -> None:
    collector = TelemetryCollector(make_settings())
    collector.bind_node_ids({collector.host_hostname: 1})
    with pytest.raises(RuntimeError):
        await collector.collect()


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_returns_valid_snapshots_for_all_nodes() -> None:
    collector = make_collector()
    specs = collector.node_specs()

    for _ in range(5):
        snapshots = await collector.collect()
        assert [s.hostname for s in snapshots] == [spec.hostname for spec in specs]
        assert len({s.timestamp for s in snapshots}) == 1
        assert [s.node_id for s in snapshots] == list(range(1, 10))

        for snapshot, spec in zip(snapshots, specs, strict=True):
            assert 0 <= snapshot.cpu_percent <= 100
            assert 0 <= snapshot.memory_percent <= 100
            assert 0 <= snapshot.disk_percent <= 100
            assert 0 <= snapshot.memory_used_mb <= spec.memory_total_mb + 1e-6
            assert snapshot.memory_total_mb == spec.memory_total_mb
            assert snapshot.link_capacity_mbps == spec.link_capacity_mbps
            assert snapshot.net_upload_kbps >= 0
            assert snapshot.net_download_kbps >= 0
            assert snapshot.process_count >= 0
            assert snapshot.uptime_seconds >= 0
            assert snapshot.latency_ms is None or snapshot.latency_ms >= 0
            assert snapshot.role is spec.role
            assert snapshot.is_simulated is spec.is_simulated
            assert snapshot.status is not NodeStatus.OFFLINE
            if snapshot.is_simulated:
                assert snapshot.latency_ms is not None
                assert 0.2 <= snapshot.latency_ms <= 15
                assert snapshot.temperature_c is not None
                assert snapshot.simulated_incident is None
                assert snapshot.net_upload_kbps <= spec.link_capacity_mbps * 1000
                assert snapshot.net_download_kbps <= spec.link_capacity_mbps * 1000


@pytest.mark.asyncio
async def test_host_snapshot_uses_background_latency_probe() -> None:
    collector = make_collector(enable_simulator=False)
    first = (await collector.collect())[0]
    second = (await collector.collect())[0]

    assert first.latency_ms in (None, 12.5)
    assert second.latency_ms == 12.5
    assert first.net_upload_kbps == 0.0  # first network sample has no delta
    assert first.net_download_kbps == 0.0
    assert first.simulated_incident is None
    assert first.is_simulated is False
    await collector.aclose()


@pytest.mark.asyncio
async def test_simulation_is_deterministic_for_a_seed(constant_diurnal: None) -> None:
    def view(snapshots: list[NodeTelemetry]) -> list[dict[str, object]]:
        return [
            s.model_dump(exclude={"timestamp", "uptime_seconds"}) for s in snapshots if s.is_simulated
        ]

    first = make_collector(simulator_incident_probability=0.05)
    second = make_collector(simulator_incident_probability=0.05)
    for _ in range(25):
        assert view(await first.collect()) == view(await second.collect())


@pytest.mark.asyncio
async def test_disk_slowly_grows(constant_diurnal: None) -> None:
    collector = make_collector(enable_simulator=True)
    first = by_host(await collector.collect())["nas-storage-01"].disk_percent
    for _ in range(200):
        last = by_host(await collector.collect())["nas-storage-01"].disk_percent
    assert last > first - 0.5  # noise only; the trend is upwards
    assert last - first < 2.0


# ---------------------------------------------------------------------------
# Incident injection
# ---------------------------------------------------------------------------


def test_inject_unknown_hostname_raises_key_error() -> None:
    collector = make_collector()
    with pytest.raises(KeyError):
        collector.inject_incident("does-not-exist", AnomalyType.CPU_SPIKE, 30)


def test_inject_on_real_host_raises_value_error() -> None:
    collector = make_collector()
    with pytest.raises(ValueError):
        collector.inject_incident(collector.host_hostname, AnomalyType.CPU_SPIKE, 30)


def test_inject_without_simulator_raises_key_error() -> None:
    collector = make_collector(enable_simulator=False)
    with pytest.raises(KeyError):
        collector.inject_incident("db-primary-01", AnomalyType.CPU_SPIKE, 30)


def test_inject_rejects_non_positive_duration() -> None:
    collector = make_collector()
    with pytest.raises(ValueError):
        collector.inject_incident("db-primary-01", AnomalyType.CPU_SPIKE, 0)


@pytest.mark.asyncio
async def test_injected_memory_leak_is_monotonic(constant_diurnal: None) -> None:
    collector = make_collector()
    await collector.collect()
    collector.inject_incident("db-primary-01", AnomalyType.MEMORY_LEAK, 120)

    series: list[float] = []
    for _ in range(20):
        node = by_host(await collector.collect())["db-primary-01"]
        assert node.simulated_incident is AnomalyType.MEMORY_LEAK
        series.append(node.memory_percent)

    assert all(later >= earlier for earlier, later in zip(series, series[1:], strict=False))
    assert series[-1] - series[0] >= 19 * 0.4 - 1e-6
    assert max(series) <= 100


@pytest.mark.asyncio
async def test_memory_leak_ends_with_service_restart(constant_diurnal: None) -> None:
    collector = make_collector()
    collector.inject_incident("cache-redis-01", AnomalyType.MEMORY_LEAK, 10)

    leak: list[NodeTelemetry] = []
    for _ in range(10):
        leak.append(by_host(await collector.collect())["cache-redis-01"])
    after = by_host(await collector.collect())["cache-redis-01"]

    assert all(node.simulated_incident is AnomalyType.MEMORY_LEAK for node in leak)
    assert after.simulated_incident is None
    assert leak[-1].memory_percent - after.memory_percent > 1.0


@pytest.mark.asyncio
async def test_injected_cpu_spike_reaches_critical(constant_diurnal: None) -> None:
    collector = make_collector()
    await collector.collect()
    collector.inject_incident("web-app-01", AnomalyType.CPU_SPIKE, 30)

    for _ in range(5):
        node = by_host(await collector.collect())["web-app-01"]
        assert node.simulated_incident is AnomalyType.CPU_SPIKE
        assert node.cpu_percent >= 90
        assert node.status is NodeStatus.CRITICAL

    # Other nodes are unaffected.
    others = [s for s in await collector.collect() if s.hostname != "web-app-01" and s.is_simulated]
    assert all(s.simulated_incident is None for s in others)


@pytest.mark.asyncio
async def test_cpu_spike_recovers_smoothly_after_duration(constant_diurnal: None) -> None:
    collector = make_collector()
    collector.inject_incident("web-app-01", AnomalyType.CPU_SPIKE, 5)
    values = [by_host(await collector.collect())["web-app-01"] for _ in range(5)]
    assert all(node.cpu_percent >= 90 for node in values)

    recovery = [by_host(await collector.collect())["web-app-01"] for _ in range(40)]
    assert recovery[0].simulated_incident is None
    assert recovery[0].cpu_percent < values[-1].cpu_percent  # decaying, not a cliff to zero
    assert recovery[0].cpu_percent > 50
    assert recovery[-1].cpu_percent < 60


@pytest.mark.asyncio
async def test_injected_bandwidth_saturation(constant_diurnal: None) -> None:
    collector = make_collector()
    collector.inject_incident("fw-core-01", AnomalyType.BANDWIDTH_SATURATION, 30)
    node = by_host(await collector.collect())["fw-core-01"]
    capacity_kbps = node.link_capacity_mbps * 1000

    assert node.simulated_incident is AnomalyType.BANDWIDTH_SATURATION
    assert 0.85 * capacity_kbps <= node.net_upload_kbps <= capacity_kbps
    assert 0.85 * capacity_kbps <= node.net_download_kbps <= capacity_kbps


@pytest.mark.asyncio
async def test_injected_critical_latency(constant_diurnal: None) -> None:
    collector = make_collector()
    collector.inject_incident("lb-edge-01", AnomalyType.CRITICAL_LATENCY, 30)
    for _ in range(5):
        node = by_host(await collector.collect())["lb-edge-01"]
        assert node.simulated_incident is AnomalyType.CRITICAL_LATENCY
        assert node.latency_ms is not None
        assert 280 <= node.latency_ms <= 900
        assert node.status is NodeStatus.CRITICAL


@pytest.mark.asyncio
async def test_injected_disk_pressure_climbs(constant_diurnal: None) -> None:
    collector = make_collector()
    baseline = by_host(await collector.collect())["dc-ad-01"].disk_percent
    collector.inject_incident("dc-ad-01", AnomalyType.DISK_PRESSURE, 30)

    series = [by_host(await collector.collect())["dc-ad-01"].disk_percent for _ in range(30)]

    assert all(later >= earlier for earlier, later in zip(series, series[1:], strict=False))
    assert series[-1] >= 93
    assert series[-1] > baseline + 40


@pytest.mark.asyncio
async def test_injected_service_down_reports_offline_node(constant_diurnal: None) -> None:
    collector = make_collector()
    before = by_host(await collector.collect())["web-app-01"]
    collector.inject_incident("web-app-01", AnomalyType.SERVICE_DOWN, 8)

    for _ in range(8):
        snapshots = await collector.collect()
        node = by_host(snapshots)["web-app-01"]
        assert node.simulated_incident is AnomalyType.SERVICE_DOWN
        assert node.status is NodeStatus.OFFLINE
        assert node.latency_ms is None
        assert node.temperature_c is None
        assert node.cpu_percent == 0.0
        assert node.memory_percent == 0.0
        assert node.memory_used_mb == 0.0
        assert node.net_upload_kbps == 0.0
        assert node.net_download_kbps == 0.0
        assert node.process_count == 0
        assert node.uptime_seconds == 0.0
        assert node.disk_percent == pytest.approx(before.disk_percent, abs=0.5)
        assert node.disk_percent > 0.0
        # Other simulated nodes are unaffected by the outage.
        others = [s for s in snapshots if s.is_simulated and s.hostname != "web-app-01"]
        assert all(s.simulated_incident is None and s.status is not NodeStatus.OFFLINE for s in others)


@pytest.mark.asyncio
async def test_service_down_recovers_with_baseline_load_and_rebooted_uptime(
    constant_diurnal: None,
) -> None:
    collector = make_collector()
    before = by_host(await collector.collect())["web-app-01"]
    assert before.uptime_seconds > 86400.0  # booted days ago
    collector.inject_incident("web-app-01", AnomalyType.SERVICE_DOWN, 5)
    for _ in range(5):
        assert by_host(await collector.collect())["web-app-01"].status is NodeStatus.OFFLINE

    recovery = [by_host(await collector.collect())["web-app-01"] for _ in range(5)]

    for node in recovery:
        assert node.simulated_incident is None
        assert node.status in (NodeStatus.ONLINE, NodeStatus.WARNING)
        assert node.cpu_percent > 5.0
        assert node.memory_percent > 20.0
        assert node.memory_used_mb > 0.0
        assert node.process_count > 0
        assert node.latency_ms is not None
        assert node.temperature_c is not None
        assert node.uptime_seconds < 60.0  # the node rebooted
    # Straight back to baseline (web-app-01 idles around 33 % CPU), not a decay from zero.
    assert 15.0 < recovery[0].cpu_percent < 55.0
    assert recovery[0].memory_percent == pytest.approx(before.memory_percent, abs=5.0)
    assert recovery[-1].uptime_seconds >= recovery[0].uptime_seconds


@pytest.mark.asyncio
async def test_service_down_ignores_residual_from_a_previous_incident(constant_diurnal: None) -> None:
    collector = make_collector()
    collector.inject_incident("db-primary-01", AnomalyType.CPU_SPIKE, 5)
    for _ in range(5):
        await collector.collect()
    collector.inject_incident("db-primary-01", AnomalyType.SERVICE_DOWN, 3)
    for _ in range(3):
        assert by_host(await collector.collect())["db-primary-01"].status is NodeStatus.OFFLINE

    node = by_host(await collector.collect())["db-primary-01"]

    assert node.simulated_incident is None
    assert node.cpu_percent < 70.0  # the stale CPU-spike residual was discarded


@pytest.mark.asyncio
async def test_injected_thermal_spike_exceeds_critical_temperature(constant_diurnal: None) -> None:
    collector = make_collector()
    before = by_host(await collector.collect())["ai-gpu-node-01"]
    collector.inject_incident("ai-gpu-node-01", AnomalyType.THERMAL_SPIKE, 30)

    series = [by_host(await collector.collect())["ai-gpu-node-01"] for _ in range(30)]

    assert all(node.simulated_incident is AnomalyType.THERMAL_SPIKE for node in series)
    assert all(node.temperature_c is not None for node in series)
    temperatures = [node.temperature_c for node in series if node.temperature_c is not None]
    assert temperatures[0] < temperatures[2] < temperatures[4]  # rising
    assert all(value > 90.0 for value in temperatures[5:])
    assert all(value <= 105.0 for value in temperatures)
    assert max(temperatures) > before.temperature_c + 15.0  # type: ignore[operator]
    # Cooling failure only: the CPU is unaffected and the node stays reachable.
    assert all(node.cpu_percent < 85.0 for node in series)
    assert all(node.status is not NodeStatus.OFFLINE for node in series)


@pytest.mark.asyncio
async def test_thermal_spike_relaxes_after_the_incident(constant_diurnal: None) -> None:
    collector = make_collector()
    baseline = by_host(await collector.collect())["db-primary-01"].temperature_c
    assert baseline is not None
    collector.inject_incident("db-primary-01", AnomalyType.THERMAL_SPIKE, 10)
    incident = [by_host(await collector.collect())["db-primary-01"] for _ in range(10)]
    peak = max(node.temperature_c for node in incident if node.temperature_c is not None)

    recovery = [by_host(await collector.collect())["db-primary-01"] for _ in range(40)]

    assert peak > 90.0
    assert recovery[0].simulated_incident is None
    assert recovery[0].temperature_c is not None
    assert 80.0 < recovery[0].temperature_c < peak  # gradual relaxation, not an instant drop
    assert recovery[-1].temperature_c is not None
    assert recovery[-1].temperature_c < 80.0
    assert recovery[-1].temperature_c == pytest.approx(baseline, abs=6.0)


@pytest.mark.parametrize("diurnal_value", [-1.0, 0.0, 1.0])
def test_normal_operation_never_reaches_the_temperature_warning(
    monkeypatch: pytest.MonkeyPatch, diurnal_value: float
) -> None:
    monkeypatch.setattr(tc, "_diurnal_factor", lambda: diurnal_value)
    settings = make_settings(simulator_incident_probability=0.0)
    simulator = tc.EnterpriseClusterSimulator(settings)

    hottest = 0.0
    for _ in range(4000):
        for hostname, sample in simulator.tick().items():
            assert sample.incident is None, hostname
            assert sample.temperature_c is not None
            hottest = max(hottest, sample.temperature_c)

    assert hottest < settings.anomaly_temperature_warning_c
    assert hottest <= tc._NORMAL_TEMPERATURE_CEILING_C


def test_every_profile_stays_under_the_ceiling_at_peak_load() -> None:
    """Even at the normal CPU ceiling, the load-driven temperature target (plus margin) is clamped."""
    for profile in tc._PROFILES:
        target = profile.temp_idle_c + profile.temp_load_c * tc._NORMAL_CPU_CEILING / 100.0
        assert min(target, tc._NORMAL_TEMPERATURE_CEILING_C) < Settings().anomaly_temperature_warning_c


@pytest.mark.asyncio
async def test_random_incidents_can_pick_service_down_and_thermal_spike() -> None:
    seen: set[AnomalyType] = set()
    for seed in range(4):
        collector = make_collector(simulator_seed=seed, simulator_incident_probability=1.0)
        for _ in range(130):
            for node in await collector.collect():
                if node.simulated_incident is AnomalyType.SERVICE_DOWN:
                    assert node.status is NodeStatus.OFFLINE
                    assert node.latency_ms is None
                    assert node.temperature_c is None
                elif node.simulated_incident is AnomalyType.THERMAL_SPIKE:
                    assert node.temperature_c is not None
                    assert node.status is not NodeStatus.OFFLINE
                if node.is_simulated and node.simulated_incident is not None:
                    seen.add(node.simulated_incident)

    assert seen == set(AnomalyType)


@pytest.mark.asyncio
async def test_injection_duration_is_converted_to_ticks(constant_diurnal: None) -> None:
    collector = make_collector(telemetry_interval_seconds=2.0)
    collector.inject_incident("db-primary-01", AnomalyType.CPU_SPIKE, 10)  # 5 ticks at 2 s

    flags = [by_host(await collector.collect())["db-primary-01"].simulated_incident for _ in range(7)]

    assert flags[:5] == [AnomalyType.CPU_SPIKE] * 5
    assert flags[5:] == [None, None]


@pytest.mark.asyncio
async def test_random_incidents_start_with_probability_one() -> None:
    collector = make_collector(simulator_incident_probability=1.0)
    snapshots = await collector.collect()
    simulated = [s for s in snapshots if s.is_simulated]

    assert len(simulated) == 8
    assert all(s.simulated_incident is not None for s in simulated)
    assert snapshots[0].simulated_incident is None  # the real host never receives incidents


@pytest.mark.asyncio
async def test_no_random_incidents_with_zero_probability() -> None:
    collector = make_collector(simulator_incident_probability=0.0)
    for _ in range(100):
        assert all(s.simulated_incident is None for s in await collector.collect())


# ---------------------------------------------------------------------------
# Host source internals
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_real_latency_probe_measures_local_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()  # use the real probe against a local listener (no external network)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        settings = make_settings(latency_probe_host="127.0.0.1", latency_probe_port=port)
        source = HostTelemetrySource(settings)
        latency = await source._probe_latency()
    finally:
        server.close()
        await server.wait_closed()

    assert latency is not None
    assert 0 <= latency < 1000


@pytest.mark.asyncio
async def test_real_latency_probe_returns_none_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()

    # Bind then release a port so nothing is listening on it.
    probe_server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = probe_server.sockets[0].getsockname()[1]
    probe_server.close()
    await probe_server.wait_closed()

    settings = make_settings(
        latency_probe_host="127.0.0.1", latency_probe_port=port, latency_probe_timeout_seconds=0.3
    )
    source = HostTelemetrySource(settings)
    assert await source._probe_latency() is None


@pytest.mark.asyncio
async def test_failing_probe_leaves_latency_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    async def failing_probe(self: HostTelemetrySource) -> float | None:
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(HostTelemetrySource, "_probe_latency", failing_probe)
    collector = make_collector(enable_simulator=False)
    await collector.collect()
    snapshot = (await collector.collect())[0]

    assert snapshot.latency_ms is None
    await collector.aclose()


# ---------------------------------------------------------------------------
# Host temperature sensors across platforms
# ---------------------------------------------------------------------------


class _Sensor:
    def __init__(self, current: object) -> None:
        self.current = current


class _Unlabelled:
    """A sensor entry without a ``current`` attribute (broken driver)."""


def test_hottest_reading_ignores_invalid_entries() -> None:
    readings = {
        "coretemp": [_Sensor(48.0), _Sensor(float("nan")), _Sensor(None), _Unlabelled()],
        "acpitz": [_Sensor("61.5"), _Sensor("n/a"), _Sensor(-273.0), _Sensor(3000.0)],
        "nvme": None,
    }
    assert tc._hottest_reading(readings) == 61.5


@pytest.mark.parametrize("readings", [{}, None, [], {"coretemp": []}, {"acpitz": [_Sensor(float("inf"))]}])
def test_hottest_reading_without_usable_sensors(readings: object) -> None:
    assert tc._hottest_reading(readings) is None


def test_host_temperature_when_platform_has_no_sensor_api(monkeypatch: pytest.MonkeyPatch) -> None:
    # Windows and macOS builds of psutil do not define sensors_temperatures at all.
    monkeypatch.delattr(tc.psutil, "sensors_temperatures", raising=False)
    source = HostTelemetrySource(Settings())
    assert source._read_temperature() is None


def test_host_temperature_when_sensor_api_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> dict[str, list[_Sensor]]:
        raise AttributeError("sensor driver unavailable")

    monkeypatch.setattr(tc.psutil, "sensors_temperatures", broken, raising=False)
    source = HostTelemetrySource(Settings())
    assert source._read_temperature() is None
