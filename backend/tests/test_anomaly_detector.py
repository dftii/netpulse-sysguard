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
from app.services import telemetry_collector
from app.services.anomaly_detector import AnomalyDetector, RollingStatistics, linear_regression
from app.services.telemetry_collector import EnterpriseClusterSimulator, classify_status

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
NODE_ID = 1
OUTLIER_PERSISTENCE = 10  # consecutive CPU outlier samples required before a statistical alert


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
    temperature: float | None = None,
    status: NodeStatus = NodeStatus.ONLINE,
) -> NodeTelemetry:
    return NodeTelemetry(
        node_id=node_id,
        hostname="db-primary-01",
        display_name="DB Primary 01",
        role=NodeRole.DATABASE,
        ip_address="10.0.0.11",
        is_simulated=True,
        status=status,
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
        temperature_c=temperature,
    )


def offline_sample(second: int, *, node_id: int = NODE_ID, **overrides: float | None) -> NodeTelemetry:
    """An unreachable node: zeroed placeholder metrics, no latency and no temperature."""
    values: dict[str, float | None] = {
        "cpu": 0.0,
        "memory": 0.0,
        "latency": None,
        "upload": 0.0,
        "download": 0.0,
        "temperature": None,
    }
    values.update(overrides)
    return make_sample(second, node_id=node_id, status=NodeStatus.OFFLINE, **values)  # type: ignore[arg-type]


def warm_up_thermal(
    detector: AnomalyDetector, rng: random.Random, samples: int = 40, centre: float = 60.0, spread: float = 1.0
) -> int:
    """Feed healthy samples with a ~60 °C temperature; returns the next free second index."""
    for second in range(samples):
        sample = stable_sample(rng, second, temperature=rng.gauss(centre, spread))
        assert detector.analyze(sample) == []
    return samples


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

    # A single critical reading is not an alert: the load has to be sustained for three samples.
    assert detector.analyze(stable_sample(rng, second, cpu=97.4)) == []
    assert detector.analyze(stable_sample(rng, second + 1, cpu=97.4)) == []

    alerts = detector.analyze(stable_sample(rng, second + 2, cpu=97.4))
    assert types_of(alerts) == [AnomalyType.CPU_SPIKE]
    alert = alerts[0]
    assert alert.node_id == NODE_ID
    assert alert.severity is AlertSeverity.CRITICAL
    assert alert.metric_name == "cpu_percent"
    assert alert.observed_value == 97.4
    assert alert.z_score is not None and alert.z_score > 3.0
    assert alert.baseline_mean == pytest.approx(30.0, abs=2.0)
    assert alert.baseline_std is not None and alert.baseline_std > 0
    assert alert.threshold == 90.0  # the critical limit of the sustained rule, not the z threshold
    assert alert.detected_at == T0 + timedelta(seconds=second + 2)
    assert "db-primary-01" in alert.message
    assert "97.4%" in alert.message
    assert "3 consecutive samples" in alert.message

    assert detector.analyze(stable_sample(rng, second + 3, cpu=98.1)) == []

    # Baseline freezing: the incident has not polluted the baseline.
    assert detector.baseline_snapshot(NODE_ID)["cpu_percent"]["mean"] == pytest.approx(30.0, abs=2.0)


def test_cpu_spike_alert_repeats_after_cooldown() -> None:
    detector = AnomalyDetector(make_settings(anomaly_cooldown_seconds=60))
    rng = random.Random(2)
    second = warm_up(detector, rng)
    fired_at: list[int] = []
    for offset in range(63):
        if detector.analyze(stable_sample(rng, second + offset, cpu=95.0)):
            fired_at.append(offset)
    # First alert on the third consecutive critical sample, the repeat exactly one cooldown later.
    assert fired_at == [2, 62]


def test_cpu_sustained_outlier_alerts_as_warning_on_tenth_consecutive_sample() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(5)
    second = warm_up(detector, rng)
    for offset in range(OUTLIER_PERSISTENCE - 1):
        assert detector.analyze(stable_sample(rng, second + offset, cpu=85.0)) == []

    tenth = second + OUTLIER_PERSISTENCE - 1
    alerts = detector.analyze(stable_sample(rng, tenth, cpu=85.0))
    assert types_of(alerts) == [AnomalyType.CPU_SPIKE]
    alert = alerts[0]
    assert alert.severity is AlertSeverity.WARNING
    assert alert.observed_value == 85.0
    assert alert.threshold == 3.0  # statistical rule: the z-score threshold
    assert alert.detected_at == T0 + timedelta(seconds=tenth)
    assert alert.z_score is not None and alert.z_score > 3.0
    assert alert.baseline_mean == pytest.approx(30.0, abs=2.0)
    assert f"{OUTLIER_PERSISTENCE} consecutive samples above baseline" in alert.message

    # Cooldown: the outlier is still there but the alert is not repeated.
    assert detector.analyze(stable_sample(rng, tenth + 1, cpu=85.0)) == []


def test_cpu_statistical_outlier_with_huge_zscore_is_warning_not_critical() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(51)
    second = warm_up(detector, rng)
    severities: list[AlertSeverity] = []
    z_scores: list[float] = []
    for offset in range(30):
        for alert in detector.analyze(stable_sample(rng, second + offset, cpu=85.0)):
            assert alert.anomaly_type is AnomalyType.CPU_SPIKE
            severities.append(alert.severity)
            assert alert.z_score is not None
            z_scores.append(alert.z_score)
    assert severities == [AlertSeverity.WARNING]
    # The old rule escalated at z >= 1.5 * threshold; this outlier is far beyond that.
    assert z_scores[0] > 3.0 * 1.5


def test_cpu_short_burst_never_alerts() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(52)
    second = warm_up(detector, rng)
    for offset in range(6):
        assert detector.analyze(stable_sample(rng, second + offset, cpu=85.0)) == []
    # The burst ends and the load returns to normal: nothing is ever reported.
    for offset in range(6, 60):
        assert detector.analyze(stable_sample(rng, second + offset)) == []


def test_cpu_outlier_streak_resets_when_the_burst_is_interrupted() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(53)
    second = warm_up(detector, rng)
    for offset in range(OUTLIER_PERSISTENCE - 1):
        assert detector.analyze(stable_sample(rng, second + offset, cpu=85.0)) == []
    # One normal sample breaks the run, so nine more high samples are still not enough.
    second += OUTLIER_PERSISTENCE - 1
    assert detector.analyze(stable_sample(rng, second)) == []
    for offset in range(1, OUTLIER_PERSISTENCE):
        assert detector.analyze(stable_sample(rng, second + offset, cpu=85.0)) == []
    alerts = detector.analyze(stable_sample(rng, second + OUTLIER_PERSISTENCE, cpu=85.0))
    assert types_of(alerts) == [AnomalyType.CPU_SPIKE]


def test_cpu_moderate_spike_below_absolute_floor_never_alerts_even_when_persistent() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(54)
    second = warm_up(detector, rng)
    # z is ~10 here, but 52% is below the 70% absolute floor: a persistent moderate rise is a
    # workload change, not an incident, so persistence alone must not turn it into an alert.
    for offset in range(3 * OUTLIER_PERSISTENCE):
        assert detector.analyze(stable_sample(rng, second + offset, cpu=52.0)) == []


def test_cpu_small_deviation_below_absolute_floor_is_ignored() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(6)
    second = warm_up(detector, rng)
    # Statistically significant (z >> 3) but below max(mean + 20, 70): not actionable.
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

    # 900 Mbps download on a 1 Gbps link (full duplex: upload idles) -> 90% utilisation -> WARNING.
    warning = detector.analyze(stable_sample(rng, second, upload=20_000.0, download=900_000.0))
    assert types_of(warning) == [AnomalyType.BANDWIDTH_SATURATION]
    assert warning[0].severity is AlertSeverity.WARNING
    assert warning[0].observed_value == pytest.approx(90.0, abs=0.01)
    assert warning[0].threshold == 85.0
    assert "download" in warning[0].message

    # Same state again is suppressed by the cooldown ...
    assert detector.analyze(stable_sample(rng, second + 1, upload=20_000.0, download=900_000.0)) == []
    # ... but escalation to CRITICAL (>= 95%) is let through.
    critical = detector.analyze(stable_sample(rng, second + 2, upload=980_000.0, download=480_000.0))
    assert types_of(critical) == [AnomalyType.BANDWIDTH_SATURATION]
    assert critical[0].severity is AlertSeverity.CRITICAL
    assert critical[0].observed_value == pytest.approx(98.0, abs=0.01)
    # And the CRITICAL state is itself rate limited.
    assert detector.analyze(stable_sample(rng, second + 3, upload=980_000.0, download=480_000.0)) == []


def test_bandwidth_below_saturation_ignored() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(13)
    second = warm_up(detector, rng)
    # 40% utilisation is a huge burst versus the 1% baseline but not a saturation risk.
    assert detector.analyze(stable_sample(rng, second, upload=400_000.0, download=400_000.0)) == []


def test_bandwidth_full_duplex_directions_are_not_summed() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(131)
    second = warm_up(detector, rng)
    # 55% up + 55% down: a half-duplex model would see 110% and CRITICAL saturation, but a full-duplex
    # link only carries 55% in each direction, which is neither saturated nor a burst (< 60%).
    assert detector.analyze(stable_sample(rng, second, upload=550_000.0, download=550_000.0)) == []
    # At 61% per direction it is a burst on a quiet link, reported as a WARNING, never saturation.
    burst = detector.analyze(stable_sample(rng, second + 1, upload=610_000.0, download=610_000.0))
    assert types_of(burst) == [AnomalyType.BANDWIDTH_SATURATION]
    assert burst[0].severity is AlertSeverity.WARNING
    assert burst[0].observed_value == pytest.approx(61.0, abs=0.01)
    assert burst[0].threshold == 3.0
    assert "burst" in burst[0].message
    assert "saturation" not in burst[0].message


@pytest.mark.parametrize(
    ("upload", "download", "direction", "expected_percent"),
    [
        (870_000.0, 20_000.0, "upload", 87.0),
        (20_000.0, 870_000.0, "download", 87.0),
        (860_000.0, 870_000.0, "download", 87.0),
    ],
)
def test_bandwidth_single_direction_saturation_names_the_busiest_direction(
    upload: float, download: float, direction: str, expected_percent: float
) -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(132)
    second = warm_up(detector, rng)
    alerts = detector.analyze(stable_sample(rng, second, upload=upload, download=download))
    assert types_of(alerts) == [AnomalyType.BANDWIDTH_SATURATION]
    assert alerts[0].severity is AlertSeverity.WARNING
    assert alerts[0].threshold == 85.0
    assert alerts[0].observed_value == pytest.approx(expected_percent, abs=0.01)
    assert f"{expected_percent:.1f}%" in alerts[0].message
    assert f"{expected_percent * 10:.1f} Mbps {direction} of 1000 Mbps" in alerts[0].message
    other = "download" if direction == "upload" else "upload"
    assert other not in alerts[0].message


def test_bandwidth_burst_on_busy_link_warns() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(14)
    for second in range(40):
        detector.analyze(stable_sample(rng, second, upload=200_000.0 + rng.gauss(0, 5_000), download=200_000.0))
    # 40% is a statistical outlier on a ~20% link but not 15 points above and >= 60%: ignored.
    assert detector.analyze(stable_sample(rng, 40, upload=400_000.0, download=300_000.0)) == []
    assert detector.analyze(stable_sample(rng, 41, upload=590_000.0, download=300_000.0)) == []

    alerts = detector.analyze(stable_sample(rng, 42, upload=700_000.0, download=300_000.0))
    assert types_of(alerts) == [AnomalyType.BANDWIDTH_SATURATION]
    assert alerts[0].severity is AlertSeverity.WARNING
    assert alerts[0].z_score is not None and alerts[0].z_score > 3.0
    assert alerts[0].observed_value == pytest.approx(70.0, abs=0.01)
    assert "burst" in alerts[0].message
    assert "upload" in alerts[0].message


def test_bandwidth_burst_requires_rise_above_a_busy_baseline() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(141)
    for second in range(40):
        detector.analyze(
            stable_sample(
                rng, second, upload=500_000.0 + rng.gauss(0, 5_000), download=500_000.0 + rng.gauss(0, 5_000)
            )
        )
    mean = detector.baseline_snapshot(NODE_ID)["net_peak_kbps"]["mean"]
    assert mean is not None and mean / 10_000.0 == pytest.approx(50.3, abs=1.0)
    # 64% clears the 60% floor and is far outside the noise (z >> 3), yet it is below mean + 15 points.
    assert detector.analyze(stable_sample(rng, 40, upload=640_000.0, download=500_000.0)) == []
    # 72% is both above the floor and more than 15 points above the baseline.
    alerts = detector.analyze(stable_sample(rng, 41, upload=720_000.0, download=500_000.0))
    assert types_of(alerts) == [AnomalyType.BANDWIDTH_SATURATION]
    assert alerts[0].severity is AlertSeverity.WARNING
    assert "burst" in alerts[0].message


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


def test_thermal_warning_on_absolute_limit() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(22)
    second = warm_up_thermal(detector, rng)
    alerts = detector.analyze(stable_sample(rng, second, temperature=83.5))
    assert types_of(alerts) == [AnomalyType.THERMAL_SPIKE]
    alert = alerts[0]
    assert alert.severity is AlertSeverity.WARNING
    assert alert.metric_name == "temperature_c"
    assert alert.observed_value == 83.5
    assert alert.threshold == 80.0
    assert alert.baseline_mean == pytest.approx(60.0, abs=1.0)
    assert alert.z_score is not None and alert.z_score > 3.0
    assert "db-primary-01" in alert.message
    assert "83.5°C" in alert.message


def test_thermal_critical_and_cooldown() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(23)
    second = warm_up_thermal(detector, rng)
    alerts = detector.analyze(stable_sample(rng, second, temperature=93.0))
    assert types_of(alerts) == [AnomalyType.THERMAL_SPIKE]
    assert alerts[0].severity is AlertSeverity.CRITICAL
    assert alerts[0].threshold == 90.0
    assert detector.analyze(stable_sample(rng, second + 1, temperature=94.0)) == []
    # Baseline freezing: the overheating samples have not polluted the baseline.
    assert detector.baseline_snapshot(NODE_ID)["temperature_c"]["mean"] == pytest.approx(60.0, abs=1.0)


def test_thermal_warning_escalates_to_critical_within_cooldown() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(24)
    second = warm_up_thermal(detector, rng)
    warning = detector.analyze(stable_sample(rng, second, temperature=85.0))
    assert [alert.severity for alert in warning] == [AlertSeverity.WARNING]
    assert detector.analyze(stable_sample(rng, second + 1, temperature=86.0)) == []
    critical = detector.analyze(stable_sample(rng, second + 2, temperature=91.0))
    assert [alert.severity for alert in critical] == [AlertSeverity.CRITICAL]


def test_thermal_zscore_jump_warns_below_absolute_limit() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(25)
    second = warm_up_thermal(detector, rng)
    alerts = detector.analyze(stable_sample(rng, second, temperature=75.0))
    assert types_of(alerts) == [AnomalyType.THERMAL_SPIKE]
    assert alerts[0].severity is AlertSeverity.WARNING
    assert alerts[0].threshold == 3.0
    assert alerts[0].z_score is not None and alerts[0].z_score > 3.0
    assert "Sudden temperature rise" in alerts[0].message


def test_thermal_rise_of_less_than_eight_degrees_is_ignored_even_with_large_zscore() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(261)
    second = warm_up_thermal(detector, rng, centre=70.0, spread=0.3)
    mean = detector.baseline_snapshot(NODE_ID)["temperature_c"]["mean"]
    assert mean == pytest.approx(70.0, abs=0.3)
    # 77.5 °C is above the 75 °C floor and ~25 sigma away, but only ~7.5 °C above the baseline:
    # a normal load-driven rise on a hot node with a quiet sensor.
    assert detector.analyze(stable_sample(rng, second, temperature=77.5)) == []
    # 78.8 °C is >= 8 °C above the baseline and still under the 80 °C absolute warning limit.
    alerts = detector.analyze(stable_sample(rng, second + 1, temperature=78.8))
    assert types_of(alerts) == [AnomalyType.THERMAL_SPIKE]
    assert alerts[0].severity is AlertSeverity.WARNING
    assert alerts[0].threshold == 3.0
    assert alerts[0].z_score is not None and alerts[0].z_score > 3.0
    assert "Sudden temperature rise" in alerts[0].message


def test_thermal_deviation_below_jump_floor_is_ignored() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(26)
    second = warm_up_thermal(detector, rng)
    # Statistically significant (z >> 3) but still a comfortable operating temperature.
    assert detector.analyze(stable_sample(rng, second, temperature=66.0)) == []


def test_thermal_critical_without_baseline() -> None:
    detector = AnomalyDetector(make_settings())
    alerts = detector.analyze(make_sample(0, temperature=95.0))
    assert types_of(alerts) == [AnomalyType.THERMAL_SPIKE]
    assert alerts[0].severity is AlertSeverity.CRITICAL
    assert alerts[0].z_score is None
    assert alerts[0].baseline_mean is None


def test_missing_temperature_is_skipped() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(27)
    for second in range(60):
        assert detector.analyze(stable_sample(rng, second, temperature=None)) == []
    assert detector.baseline_snapshot(NODE_ID)["temperature_c"] == {"count": 0, "mean": None, "std": None}


def test_temperature_is_part_of_baseline_snapshot() -> None:
    detector = AnomalyDetector(make_settings())
    assert detector.baseline_snapshot(NODE_ID)["temperature_c"] == {"count": 0, "mean": None, "std": None}
    rng = random.Random(28)
    warm_up_thermal(detector, rng, samples=30)
    snapshot = detector.baseline_snapshot(NODE_ID)
    assert set(snapshot) == {
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "latency_ms",
        "net_peak_kbps",
        "temperature_c",
    }
    assert snapshot["temperature_c"]["count"] == 30
    assert snapshot["temperature_c"]["mean"] == pytest.approx(60.0, abs=1.0)


def test_service_down_below_threshold_is_silent() -> None:
    detector = AnomalyDetector(make_settings())
    assert detector.analyze(offline_sample(0)) == []
    assert detector.analyze(offline_sample(1)) == []


def test_service_down_alert_at_threshold_then_cooldown() -> None:
    detector = AnomalyDetector(make_settings())
    assert detector.analyze(offline_sample(0)) == []
    assert detector.analyze(offline_sample(1)) == []
    alerts = detector.analyze(offline_sample(2))
    assert types_of(alerts) == [AnomalyType.SERVICE_DOWN]
    alert = alerts[0]
    assert alert.node_id == NODE_ID
    assert alert.severity is AlertSeverity.CRITICAL
    assert alert.metric_name == "offline_samples"
    assert alert.observed_value == 3.0
    assert alert.threshold == 3.0
    assert alert.baseline_mean is None and alert.baseline_std is None and alert.z_score is None
    assert alert.detected_at == T0 + timedelta(seconds=2)
    assert "db-primary-01" in alert.message
    assert "3 consecutive samples" in alert.message
    assert "~3s" in alert.message

    # Still down, same severity: suppressed by the cooldown.
    assert detector.analyze(offline_sample(3)) == []
    assert detector.analyze(offline_sample(4)) == []


def test_service_down_repeats_after_cooldown() -> None:
    detector = AnomalyDetector(make_settings(anomaly_cooldown_seconds=10))
    assert types_of([a for second in range(3) for a in detector.analyze(offline_sample(second))]) == [
        AnomalyType.SERVICE_DOWN
    ]
    assert detector.analyze(offline_sample(9)) == []
    repeated = detector.analyze(offline_sample(12))
    assert types_of(repeated) == [AnomalyType.SERVICE_DOWN]
    assert repeated[0].observed_value == 5.0  # samples seen so far, not seconds elapsed
    assert "~13s" in repeated[0].message


def test_service_down_threshold_is_configurable() -> None:
    detector = AnomalyDetector(make_settings(anomaly_service_down_samples=1))
    alerts = detector.analyze(offline_sample(0))
    assert types_of(alerts) == [AnomalyType.SERVICE_DOWN]
    assert alerts[0].threshold == 1.0


def test_service_down_counter_resets_on_recovery() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(29)
    assert detector.analyze(offline_sample(0)) == []
    assert detector.analyze(offline_sample(1)) == []
    assert detector.analyze(stable_sample(rng, 2)) == []  # node is back
    assert detector.analyze(offline_sample(3)) == []
    assert detector.analyze(offline_sample(4)) == []  # only 2 consecutive since recovery
    alerts = detector.analyze(offline_sample(5))
    assert types_of(alerts) == [AnomalyType.SERVICE_DOWN]
    assert alerts[0].observed_value == 3.0
    # Downtime is measured from the first sample of the *current* outage.
    assert "~3s" in alerts[0].message


def test_offline_samples_do_not_alter_baselines() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(30)
    second = warm_up_thermal(detector, rng)
    before = detector.baseline_snapshot(NODE_ID)
    for offset in range(10):
        detector.analyze(offline_sample(second + offset))
    assert detector.baseline_snapshot(NODE_ID) == before

    # The baseline is still intact after recovery: a real sustained spike is detected against it.
    for offset in range(2):
        assert detector.analyze(stable_sample(rng, second + 10 + offset, cpu=97.0, temperature=60.0)) == []
    alerts = detector.analyze(stable_sample(rng, second + 12, cpu=97.0, temperature=60.0))
    assert types_of(alerts) == [AnomalyType.CPU_SPIKE]
    assert alerts[0].baseline_mean == pytest.approx(30.0, abs=2.0)


def test_offline_samples_never_run_other_evaluators() -> None:
    detector = AnomalyDetector(make_settings())
    # Values that would trip disk, CPU, latency, bandwidth and thermal rules if they were evaluated.
    hot = {
        "cpu": 99.0,
        "disk": 97.0,
        "latency": 400.0,
        "upload": 600_000.0,
        "download": 600_000.0,
        "temperature": 99.0,
    }
    assert detector.analyze(offline_sample(0, **hot)) == []
    assert detector.analyze(offline_sample(1, **hot)) == []
    assert types_of(detector.analyze(offline_sample(2, **hot))) == [AnomalyType.SERVICE_DOWN]
    for metric in detector.baseline_snapshot(NODE_ID).values():
        assert metric == {"count": 0, "mean": None, "std": None}


def test_service_down_is_tracked_per_node() -> None:
    detector = AnomalyDetector(make_settings())
    for second in range(2):
        detector.analyze(offline_sample(second, node_id=1))
        detector.analyze(offline_sample(second, node_id=2))
    assert types_of(detector.analyze(offline_sample(2, node_id=1))) == [AnomalyType.SERVICE_DOWN]
    # Node 2 recovers before reaching the threshold and never alerts.
    assert detector.analyze(make_sample(2, node_id=2)) == []
    assert detector.analyze(offline_sample(3, node_id=2)) == []


def test_at_most_one_alert_per_type_per_sample() -> None:
    detector = AnomalyDetector(make_settings())
    rng = random.Random(19)
    second = warm_up(detector, rng)
    # CPU needs three consecutive critical samples; nothing else is abnormal yet.
    assert detector.analyze(stable_sample(rng, second, cpu=99.0)) == []
    assert detector.analyze(stable_sample(rng, second + 1, cpu=99.0)) == []
    alerts = detector.analyze(
        stable_sample(
            rng, second + 2, cpu=99.0, disk=97.0, latency=400.0, upload=960_000.0, download=480_000.0
        )
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
                stable_sample(rng, 41, cpu=97.0),
                stable_sample(rng, 42, cpu=97.0, disk=95.0, latency=320.0),
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


# ---------------------------------------------------------------------------
# Quiet-cluster regression: healthy simulated traffic must not raise alarms
# ---------------------------------------------------------------------------

QUIET_TICKS = 1800  # 30 simulated minutes per seed


def run_quiet_cluster(seed: int) -> list[AnomalyAlertCreate]:
    """Run the incident-free simulator through the detector and return every alert it raised."""
    settings = make_settings(simulator_seed=seed, simulator_incident_probability=0.0)
    simulator = EnterpriseClusterSimulator(settings)
    specs = {spec.hostname: spec for spec in simulator.specs()}
    node_ids = {hostname: index for index, hostname in enumerate(simulator.hostnames, start=1)}
    detector = AnomalyDetector(settings)
    alerts: list[AnomalyAlertCreate] = []
    for tick in range(QUIET_TICKS):
        timestamp = T0 + timedelta(seconds=tick)
        for hostname, sim in simulator.tick().items():
            spec = specs[hostname]
            sample = NodeTelemetry(
                node_id=node_ids[hostname],
                hostname=hostname,
                display_name=spec.display_name,
                role=spec.role,
                ip_address=spec.ip_address,
                is_simulated=True,
                status=classify_status(sim.cpu_percent, sim.memory_percent, sim.disk_percent, sim.latency_ms),
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
            assert sim.incident is None  # the incident engine is disabled for this scenario
            alerts.extend(detector.analyze(sample))
    return alerts


@pytest.mark.parametrize("diurnal", [-1.0, 0.0, 1.0], ids=["night-trough", "midday", "afternoon-peak"])
@pytest.mark.parametrize("seed", [0, 1, 2])
def test_quiet_simulated_cluster_stays_quiet(monkeypatch: pytest.MonkeyPatch, seed: int, diurnal: float) -> None:
    monkeypatch.setattr(telemetry_collector, "_diurnal_factor", lambda: diurnal)
    alerts = run_quiet_cluster(seed)
    summary = [(alert.node_id, alert.anomaly_type.value, alert.severity.value, alert.message) for alert in alerts]
    # Normal operation of the simulated cluster (bursts, diurnal load, noise) must never page anyone.
    assert alerts == [], summary
