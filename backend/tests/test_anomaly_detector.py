"""Unit tests for the statistical anomaly detection engine."""

from __future__ import annotations

import random
import statistics
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import models  # noqa: F401  (registers mappers on Base.metadata)
from app.config import Settings
from app.database import Base
from app.enums import AlertSeverity, AnomalyType, NodeRole, NodeStatus
from app.models import AnomalyAlert, Node
from app.schemas import AnomalyAlertCreate, NodeTelemetry
from app.services.anomaly_detector import AnomalyDetector, RollingStatistics, linear_regression

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
NODE_ID = 1


def make_settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def make_sample(
    second: int,
    *,
    node_id: int = NODE_ID,
    cpu: float = 30.0,
    memory: float = 50.0,
    disk: float = 55.0,
    latency: float | None = 20.0,
    upload: float = 10_000.0,
    download: float = 10_000.0,
    link_mbps: float = 1000.0,
) -> NodeTelemetry:
    return NodeTelemetry(
        node_id=node_id,
        hostname="db-primary-01",
        display_name="DB Primary 01",
        role=NodeRole.DATABASE,
        ip_address="10.0.0.11",
        is_simulated=True,
        status=NodeStatus.ONLINE,
        timestamp=T0 + timedelta(seconds=second),
        memory_total_mb=65536.0,
        link_capacity_mbps=link_mbps,
        uptime_seconds=3600.0 + second,
        cpu_percent=cpu,
        memory_percent=memory,
        memory_used_mb=memory / 100.0 * 65536.0,
        disk_percent=disk,
        latency_ms=latency,
        net_upload_kbps=upload,
        net_download_kbps=download,
    )


def stable_sample(rng: random.Random, second: int, **overrides: float | None) -> NodeTelemetry:
    """A healthy sample with seeded noise around a calm operating point."""
    values: dict[str, float | None] = {
        "cpu": min(max(rng.gauss(30.0, 2.0), 0.0), 100.0),
        "memory": min(max(rng.gauss(50.0, 0.5), 0.0), 100.0),
        "disk": min(max(rng.gauss(55.0, 0.2), 0.0), 100.0),
        "latency": max(rng.gauss(20.0, 2.0), 0.1),
        "upload": max(rng.gauss(10_000.0, 800.0), 0.0),
        "download": max(rng.gauss(10_000.0, 800.0), 0.0),
    }
    values.update(overrides)
    return make_sample(second, **values)  # type: ignore[arg-type]


def warm_up(detector: AnomalyDetector, rng: random.Random, samples: int = 40) -> int:
    """Feed healthy samples; returns the next free second index. Must produce no alerts."""
    for second in range(samples):
        assert detector.analyze(stable_sample(rng, second)) == []
    return samples


def types_of(alerts: list[AnomalyAlertCreate]) -> list[AnomalyType]:
    return [alert.anomaly_type for alert in alerts]


# ---------------------------------------------------------------------------
# RollingStatistics
# ---------------------------------------------------------------------------


def test_rolling_statistics_matches_statistics_module_including_eviction() -> None:
    rng = random.Random(7)
    window = 25
    rolling = RollingStatistics(window)
    history: list[float] = []
    for _ in range(300):
        value = rng.gauss(100.0, 15.0)
        rolling.push(value)
        history.append(value)
        expected = history[-window:]
        assert rolling.count == len(expected)
        assert rolling.mean == pytest.approx(statistics.fmean(expected), abs=1e-9)
        assert rolling.std == pytest.approx(statistics.pstdev(expected), abs=1e-7)
    assert rolling.values() == history[-window:]


def test_rolling_statistics_zscore_guards() -> None:
    rolling = RollingStatistics(10)
    assert rolling.zscore(5.0) is None
    rolling.push(5.0)
    assert rolling.zscore(5.0) is None  # fewer than two samples
    rolling.push(5.0)
    assert rolling.std == 0.0
    assert rolling.zscore(9.0) is None  # zero variance

    varied = RollingStatistics(10)
    for value in (1.0, 2.0, 3.0, 4.0, 5.0):
        varied.push(value)
    assert varied.zscore(3.0) == pytest.approx(0.0)
    assert varied.zscore(3.0 + varied.std) == pytest.approx(1.0)


def test_rolling_statistics_variance_never_negative_on_constant_stream() -> None:
    rolling = RollingStatistics(5)
    for _ in range(10_000):
        rolling.push(0.1 + 1e9)
    assert rolling.std >= 0.0
    assert rolling.std < 1e-3


def test_rolling_statistics_window_of_one() -> None:
    rolling = RollingStatistics(1)
    rolling.push(3.0)
    rolling.push(8.0)
    assert rolling.count == 1
    assert rolling.mean == 8.0
    assert rolling.std == 0.0


# ---------------------------------------------------------------------------
# linear_regression
# ---------------------------------------------------------------------------


def test_linear_regression_perfect_line() -> None:
    slope, r_squared = linear_regression([3.0 + 0.5 * index for index in range(40)])
    assert slope == pytest.approx(0.5)
    assert r_squared == pytest.approx(1.0)


def test_linear_regression_negative_slope() -> None:
    slope, r_squared = linear_regression([100.0 - 2.0 * index for index in range(10)])
    assert slope == pytest.approx(-2.0)
    assert r_squared == pytest.approx(1.0)


def test_linear_regression_degenerate_inputs() -> None:
    assert linear_regression([]) == (0.0, 0.0)
    assert linear_regression([5.0]) == (0.0, 0.0)
    assert linear_regression([42.0] * 30) == (0.0, 0.0)


def test_linear_regression_noise_has_low_r_squared() -> None:
    rng = random.Random(3)
    _slope, r_squared = linear_regression([rng.gauss(50.0, 1.0) for _ in range(60)])
    assert r_squared < 0.3


# ---------------------------------------------------------------------------
# Detection behaviour
# ---------------------------------------------------------------------------


def test_no_zscore_alerts_during_warm_up() -> None:
    settings = make_settings()
    detector = AnomalyDetector(settings)
    rng = random.Random(11)
    for second in range(settings.anomaly_min_samples - 1):
        # A CPU jump while the baseline is still being learned must stay silent.
        cpu = 95.0 if second == settings.anomaly_min_samples - 2 else None
        overrides = {"cpu": cpu} if cpu is not None else {}
        assert detector.analyze(stable_sample(rng, second, **overrides)) == []


def test_stable_noise_produces_no_alerts() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(42)
    for second in range(200):
        assert detector.analyze(stable_sample(rng, second)) == []
    snapshot = detector.baseline_snapshot(NODE_ID)
    assert snapshot["cpu_percent"]["count"] == 60
    assert snapshot["cpu_percent"]["mean"] == pytest.approx(30.0, abs=2.0)


def test_cpu_spike_alert_and_cooldown() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(1)
    second = warm_up(detector, rng)

    alerts = detector.analyze(stable_sample(rng, second, cpu=97.4))
    assert types_of(alerts) == [AnomalyType.CPU_SPIKE]
    alert = alerts[0]
    assert alert.node_id == NODE_ID
    assert alert.severity is AlertSeverity.CRITICAL
    assert alert.metric_name == "cpu_percent"
    assert alert.observed_value == 97.4
    assert alert.z_score is not None and alert.z_score > 3.0
    assert alert.baseline_mean == pytest.approx(30.0, abs=2.0)
    assert alert.baseline_std is not None and alert.baseline_std > 0
    assert alert.threshold == 3.0
    assert alert.detected_at == T0 + timedelta(seconds=second)
    assert "db-primary-01" in alert.message
    assert "97.4%" in alert.message

    assert detector.analyze(stable_sample(rng, second + 1, cpu=98.1)) == []

    # Baseline freezing: the incident has not polluted the baseline.
    assert detector.baseline_snapshot(NODE_ID)["cpu_percent"]["mean"] == pytest.approx(30.0, abs=2.0)


def test_cpu_spike_alert_repeats_after_cooldown() -> None:
    detector = AnomalyDetector(make_settings(anomaly_cooldown_seconds=60))
    rng = random.Random(2)
    second = warm_up(detector, rng)
    assert types_of(detector.analyze(stable_sample(rng, second, cpu=95.0))) == [AnomalyType.CPU_SPIKE]
    assert detector.analyze(stable_sample(rng, second + 30, cpu=95.0)) == []
    assert types_of(detector.analyze(stable_sample(rng, second + 60, cpu=95.0))) == [AnomalyType.CPU_SPIKE]


def test_cpu_warning_for_moderate_spike() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(5)
    second = warm_up(detector, rng)
    alerts = detector.analyze(stable_sample(rng, second, cpu=52.0))
    # z is ~11 here which is beyond threshold * 1.5, so the spike is escalated.
    assert types_of(alerts) == [AnomalyType.CPU_SPIKE]
    assert alerts[0].severity is AlertSeverity.CRITICAL


def test_cpu_small_deviation_below_absolute_floor_is_ignored() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(6)
    second = warm_up(detector, rng)
    # Statistically significant (z >> 3) but below max(mean + 10, 50): not actionable.
    assert detector.analyze(stable_sample(rng, second, cpu=42.0)) == []


def test_sustained_critical_cpu_without_zscore_baseline() -> None:
    # Constant 95% load from the very first sample: no z-score is ever available,
    # so only the sustained absolute rule can fire (on the third consecutive sample).
    detector = AnomalyDetector(make_settings())
    assert detector.analyze(make_sample(0, cpu=95.0)) == []
    assert detector.analyze(make_sample(1, cpu=95.0)) == []
    alerts = detector.analyze(make_sample(2, cpu=95.0))
    assert types_of(alerts) == [AnomalyType.CPU_SPIKE]
    assert alerts[0].severity is AlertSeverity.CRITICAL
    assert alerts[0].z_score is None
    assert alerts[0].threshold == 90.0


def test_baseline_adapts_to_sustained_new_normal() -> None:
    settings = make_settings()
    detector = AnomalyDetector(settings)
    rng = random.Random(8)
    second = warm_up(detector, rng)
    for offset in range(3 * settings.anomaly_window_size):
        detector.analyze(stable_sample(rng, second + offset, cpu=70.0 + rng.gauss(0.0, 2.0)))
    assert detector.baseline_snapshot(NODE_ID)["cpu_percent"]["mean"] == pytest.approx(70.0, abs=2.0)


def test_memory_leak_ramp_detected() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(9)
    first_alert: AnomalyAlertCreate | None = None
    alert_count = 0
    for second in range(95):
        memory = 40.0 + 0.2 * second + rng.gauss(0.0, 0.05)
        alerts = detector.analyze(stable_sample(rng, second, memory=memory))
        for alert in alerts:
            assert alert.anomaly_type is AnomalyType.MEMORY_LEAK
            alert_count += 1
            first_alert = first_alert or alert
    assert first_alert is not None
    assert alert_count == 2  # default cooldown (60s) allows one repeat within 95 samples
    assert first_alert.severity is AlertSeverity.WARNING
    assert first_alert.metric_name == "memory_percent"
    assert first_alert.threshold == 0.08
    assert "db-primary-01" in first_alert.message
    assert "exhaustion" in first_alert.message


def test_memory_leak_critical_when_nearly_exhausted() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(10)
    severities: list[AlertSeverity] = []
    for second in range(60):
        alerts = detector.analyze(stable_sample(rng, second, memory=70.0 + 0.5 * second))
        severities.extend(alert.severity for alert in alerts)
    assert AlertSeverity.CRITICAL in severities


def test_flat_memory_never_flagged() -> None:
    detector = AnomalyDetector(make_settings())
    for second in range(150):
        assert detector.analyze(make_sample(second, memory=64.0)) == []


def test_bandwidth_saturation_and_escalation() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(12)
    second = warm_up(detector, rng)

    # 900 Mbps on a 1 Gbps link -> 90% utilisation -> WARNING.
    warning = detector.analyze(stable_sample(rng, second, upload=450_000.0, download=450_000.0))
    assert types_of(warning) == [AnomalyType.BANDWIDTH_SATURATION]
    assert warning[0].severity is AlertSeverity.WARNING
    assert warning[0].observed_value == pytest.approx(90.0, abs=0.01)
    assert warning[0].threshold == 85.0

    # Same state again is suppressed by the cooldown ...
    assert detector.analyze(stable_sample(rng, second + 1, upload=450_000.0, download=450_000.0)) == []
    # ... but escalation to CRITICAL (>= 95%) is let through.
    critical = detector.analyze(stable_sample(rng, second + 2, upload=490_000.0, download=480_000.0))
    assert types_of(critical) == [AnomalyType.BANDWIDTH_SATURATION]
    assert critical[0].severity is AlertSeverity.CRITICAL
    # And the CRITICAL state is itself rate limited.
    assert detector.analyze(stable_sample(rng, second + 3, upload=490_000.0, download=480_000.0)) == []


def test_bandwidth_below_saturation_ignored() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(13)
    second = warm_up(detector, rng)
    # 40% utilisation is a huge burst versus the 2% baseline but not a saturation risk.
    assert detector.analyze(stable_sample(rng, second, upload=200_000.0, download=200_000.0)) == []


def test_bandwidth_burst_on_busy_link_warns() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(14)
    for second in range(40):
        detector.analyze(stable_sample(rng, second, upload=200_000.0 + rng.gauss(0, 5_000), download=200_000.0))
    alerts = detector.analyze(stable_sample(rng, 40, upload=400_000.0, download=300_000.0))
    assert types_of(alerts) == [AnomalyType.BANDWIDTH_SATURATION]
    assert alerts[0].severity is AlertSeverity.WARNING
    assert alerts[0].z_score is not None and alerts[0].z_score > 3.0
    assert alerts[0].observed_value == pytest.approx(70.0, abs=0.01)


def test_critical_latency_absolute_threshold() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(15)
    second = warm_up(detector, rng)
    alerts = detector.analyze(stable_sample(rng, second, latency=310.0))
    assert types_of(alerts) == [AnomalyType.CRITICAL_LATENCY]
    assert alerts[0].severity is AlertSeverity.CRITICAL
    assert alerts[0].threshold == 250.0
    assert alerts[0].metric_name == "latency_ms"
    assert "310.0 ms" in alerts[0].message


def test_latency_relative_jump_warns_then_escalates() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(16)
    second = warm_up(detector, rng)
    warning = detector.analyze(stable_sample(rng, second, latency=120.0))
    assert types_of(warning) == [AnomalyType.CRITICAL_LATENCY]
    assert warning[0].severity is AlertSeverity.WARNING
    assert warning[0].threshold == 3.0
    critical = detector.analyze(stable_sample(rng, second + 1, latency=300.0))
    assert types_of(critical) == [AnomalyType.CRITICAL_LATENCY]
    assert critical[0].severity is AlertSeverity.CRITICAL


def test_missing_latency_is_skipped() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(17)
    for second in range(60):
        assert detector.analyze(stable_sample(rng, second, latency=None)) == []
    assert detector.baseline_snapshot(NODE_ID)["latency_ms"] == {"count": 0, "mean": None, "std": None}


def test_disk_pressure_critical_without_baseline() -> None:
    detector = AnomalyDetector(make_settings())
    alerts = detector.analyze(make_sample(0, disk=94.5))
    assert types_of(alerts) == [AnomalyType.DISK_PRESSURE]
    assert alerts[0].severity is AlertSeverity.CRITICAL
    assert alerts[0].z_score is None
    assert alerts[0].baseline_mean is None
    assert alerts[0].threshold == 92.0


def test_disk_jump_warning_then_critical_escalation_within_cooldown() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(18)
    for second in range(40):
        detector.analyze(stable_sample(rng, second, disk=70.0 + rng.gauss(0.0, 0.2)))
    warning = detector.analyze(stable_sample(rng, 40, disk=85.0))
    assert types_of(warning) == [AnomalyType.DISK_PRESSURE]
    assert warning[0].severity is AlertSeverity.WARNING
    assert detector.analyze(stable_sample(rng, 41, disk=86.0)) == []
    critical = detector.analyze(stable_sample(rng, 42, disk=93.0))
    assert types_of(critical) == [AnomalyType.DISK_PRESSURE]
    assert critical[0].severity is AlertSeverity.CRITICAL


def test_at_most_one_alert_per_type_per_sample() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(19)
    second = warm_up(detector, rng)
    alerts = detector.analyze(
        stable_sample(rng, second, cpu=99.0, disk=97.0, latency=400.0, upload=500_000.0, download=480_000.0)
    )
    kinds = types_of(alerts)
    assert len(kinds) == len(set(kinds))
    assert set(kinds) == {
        AnomalyType.CPU_SPIKE,
        AnomalyType.DISK_PRESSURE,
        AnomalyType.CRITICAL_LATENCY,
        AnomalyType.BANDWIDTH_SATURATION,
    }


def test_nodes_are_isolated_and_reset_works() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(20)
    for second in range(40):
        detector.analyze(stable_sample(rng, second))
    # A different node has no baseline, so the same jump is not a z-score anomaly there.
    assert detector.analyze(make_sample(0, node_id=2, cpu=60.0)) == []
    assert detector.baseline_snapshot(1)["cpu_percent"]["count"] == 40
    assert detector.baseline_snapshot(2)["cpu_percent"]["count"] == 1

    detector.reset(1)
    assert detector.baseline_snapshot(1)["cpu_percent"] == {"count": 0, "mean": None, "std": None}
    assert detector.baseline_snapshot(2)["cpu_percent"]["count"] == 1
    detector.reset()
    assert detector.baseline_snapshot(2)["cpu_percent"]["count"] == 0


def test_cooldown_zero_allows_every_alert() -> None:
    detector = AnomalyDetector(make_settings(anomaly_cooldown_seconds=0))
    for second in range(3):
        alerts = detector.analyze(make_sample(second, disk=95.0))
        assert types_of(alerts) == [AnomalyType.DISK_PRESSURE]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_and_persist_stores_alerts() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)

        async with session_factory() as session:
            session.add(
                Node(
                    id=NODE_ID,
                    hostname="db-primary-01",
                    display_name="DB Primary 01",
                    role=NodeRole.DATABASE,
                    ip_address="10.0.0.11",
                    os_name="Ubuntu 24.04",
                    location="eu-west-1",
                    is_simulated=True,
                    cpu_cores=16,
                    memory_total_mb=65536.0,
                    disk_total_gb=2000.0,
                    link_capacity_mbps=1000.0,
                    status=NodeStatus.ONLINE,
                )
            )
            await session.commit()

            detector = AnomalyDetector(make_settings())
            rng = random.Random(21)
            warm_samples = [stable_sample(rng, second) for second in range(40)]
            assert await detector.analyze_and_persist(session, warm_samples) == []
            count = await session.scalar(select(func.count()).select_from(AnomalyAlert))
            assert count == 0

            incident = [
                stable_sample(rng, 40, cpu=97.0),
                stable_sample(rng, 41, disk=95.0, latency=320.0),
            ]
            persisted = await detector.analyze_and_persist(session, incident)
            assert {row.anomaly_type for row in persisted} == {
                AnomalyType.CPU_SPIKE,
                AnomalyType.DISK_PRESSURE,
                AnomalyType.CRITICAL_LATENCY,
            }
            assert all(row.id is not None for row in persisted)
            assert all(row.acknowledged is False for row in persisted)

            stored = (await session.scalars(select(AnomalyAlert).order_by(AnomalyAlert.id))).all()
            assert len(stored) == 3
            assert {row.node_id for row in stored} == {NODE_ID}
            cpu_row = next(row for row in stored if row.anomaly_type is AnomalyType.CPU_SPIKE)
            assert cpu_row.observed_value == 97.0
            assert cpu_row.z_score is not None and cpu_row.z_score > 3.0
            assert cpu_row.severity is AlertSeverity.CRITICAL
    finally:
        await engine.dispose()
