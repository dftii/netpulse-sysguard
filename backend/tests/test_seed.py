"""Tests for the demo-data seeder (backend/seed.py): coverage, consistency, idempotency and reset."""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete, event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import seed
from app import crud
from app.config import get_settings
from app.database import SessionLocal, dispose_db
from app.enums import AlertSeverity, AnomalyType, NodeRole, PortState, RiskLevel
from app.models import AnomalyAlert, MetricSample, Node, PortAudit, PortFinding
from app.schemas import AnomalyAlertCreate, MetricValues
from app.services import anomaly_detector, telemetry_collector
from app.services.network_scanner import COMMON_PORTS, calculate_risk_score
from app.services.telemetry_collector import EnterpriseClusterSimulator

NOW = datetime(2026, 3, 14, 12, 0, 0, tzinfo=UTC)
SIMULATED_HOSTNAMES = sorted(spec.hostname for spec in EnterpriseClusterSimulator(get_settings()).specs())

SessionFactory = async_sessionmaker[AsyncSession]


def _utc(moment: datetime) -> datetime:
    """SQLite returns naive datetimes; everything stored by the seeder is UTC."""
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


@pytest.fixture
async def session_factory(tmp_path: Path) -> AsyncIterator[SessionFactory]:
    """A private, empty SQLite database per test (production PRAGMAs included) so tests never interfere."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'seed.db').as_posix()}")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


async def _scalars(factory: SessionFactory, statement: Any) -> list[Any]:
    async with factory() as session:
        return list((await session.execute(statement)).scalars())


async def _count(factory: SessionFactory, model: Any, *conditions: Any) -> int:
    async with factory() as session:
        return int(await session.scalar(select(func.count()).select_from(model).where(*conditions)) or 0)


async def _node_ids(factory: SessionFactory) -> dict[str, int]:
    nodes: list[Node] = await _scalars(factory, select(Node))
    return {node.hostname: node.id for node in nodes}


async def _table_counts(factory: SessionFactory) -> dict[str, int]:
    return {
        "nodes": await _count(factory, Node),
        "metrics": await _count(factory, MetricSample),
        "alerts": await _count(factory, AnomalyAlert),
        "audits": await _count(factory, PortAudit),
        "findings": await _count(factory, PortFinding),
    }


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


async def test_seeds_the_eight_simulator_nodes(session_factory: SessionFactory) -> None:
    report = await seed.seed_database(session_factory, now=NOW)

    nodes: list[Node] = await _scalars(session_factory, select(Node))
    assert sorted(node.hostname for node in nodes) == SIMULATED_HOSTNAMES
    assert len(nodes) == 8
    assert all(node.is_simulated for node in nodes)
    assert not any(node.role is NodeRole.HOST for node in nodes)
    assert report.nodes_total == 8
    assert report.nodes_created == 8


async def test_node_attributes_come_from_the_simulator_specs(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    specs = {spec.hostname: spec for spec in EnterpriseClusterSimulator(get_settings()).specs()}

    for node in await _scalars(session_factory, select(Node)):
        spec = specs[node.hostname]
        assert node.ip_address == spec.ip_address
        assert node.role is spec.role
        assert node.memory_total_mb == spec.memory_total_mb
        assert node.link_capacity_mbps == spec.link_capacity_mbps


async def test_every_plan_targets_a_simulator_node() -> None:
    assert {plan.hostname for plan in seed.INCIDENT_PLANS} <= set(SIMULATED_HOSTNAMES)
    assert {plan.hostname for plan in seed.AUDIT_PLANS} == set(SIMULATED_HOSTNAMES)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


async def test_each_node_gets_200_samples_inside_the_last_24_hours(session_factory: SessionFactory) -> None:
    report = await seed.seed_database(session_factory, now=NOW)

    ids = await _node_ids(session_factory)
    window_start = NOW - timedelta(hours=24)
    for hostname, node_id in ids.items():
        samples: list[MetricSample] = await _scalars(
            session_factory,
            select(MetricSample).where(MetricSample.node_id == node_id).order_by(MetricSample.timestamp),
        )
        assert len(samples) == seed.SAMPLES_PER_NODE == 200, hostname
        stamps = [_utc(sample.timestamp) for sample in samples]
        assert all(window_start <= stamp <= NOW for stamp in stamps), hostname
        assert stamps == sorted(set(stamps)), f"{hostname}: timestamps must be unique"
        gaps = [(later - earlier).total_seconds() for earlier, later in zip(stamps, stamps[1:], strict=False)]
        assert max(gaps) < 2 * 432 and min(gaps) > 0, f"{hostname}: samples must be evenly spread"
        assert stamps[0] - window_start < timedelta(minutes=10)
        assert NOW - stamps[-1] < timedelta(minutes=10)
    assert report.metrics_inserted == 8 * 200


async def test_metric_values_respect_schema_bounds_and_profile_capacity(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    nodes: dict[int, Node] = {node.id: node for node in await _scalars(session_factory, select(Node))}

    for sample in await _scalars(session_factory, select(MetricSample)):
        node = nodes[sample.node_id]
        MetricValues(
            cpu_percent=sample.cpu_percent,
            memory_percent=sample.memory_percent,
            memory_used_mb=sample.memory_used_mb,
            disk_percent=sample.disk_percent,
            latency_ms=sample.latency_ms,
            net_upload_kbps=sample.net_upload_kbps,
            net_download_kbps=sample.net_download_kbps,
            process_count=sample.process_count,
            temperature_c=sample.temperature_c,
        )
        assert sample.memory_used_mb <= node.memory_total_mb
        capacity_kbps = node.link_capacity_mbps * 1000.0
        # Full duplex: every direction has the whole capacity on its own.
        assert sample.net_upload_kbps <= capacity_kbps * 1.0001
        assert sample.net_download_kbps <= capacity_kbps * 1.0001


async def test_quiet_samples_stay_near_the_profile_baselines(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    profiles = {profile.hostname: profile for profile in seed._PROFILES}
    ids = await _node_ids(session_factory)

    for hostname, node_id in ids.items():
        profile = profiles[hostname]
        samples = [
            sample
            for sample in await _scalars(session_factory, select(MetricSample).where(MetricSample.node_id == node_id))
            if sample.latency_ms is not None and sample.latency_ms < 15.0 and sample.cpu_percent < 89.0
        ]
        assert len(samples) > 150
        mean_cpu = sum(sample.cpu_percent for sample in samples) / len(samples)
        mean_memory = sum(sample.memory_percent for sample in samples) / len(samples)
        mean_latency = sum(sample.latency_ms or 0.0 for sample in samples) / len(samples)
        assert abs(mean_cpu - profile.base_cpu) < max(8.0, profile.cpu_diurnal), hostname
        assert abs(mean_memory - profile.base_memory) < 6.0, hostname
        assert 0.5 * profile.base_latency_ms < mean_latency < 3.0 * profile.base_latency_ms, hostname


async def test_service_down_windows_have_no_latency_and_zero_cpu_and_traffic(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    ids = await _node_ids(session_factory)

    expected = {
        plan.hostname: plan.length for plan in seed.INCIDENT_PLANS if plan.kind is AnomalyType.SERVICE_DOWN
    }
    assert expected
    for hostname, node_id in ids.items():
        gap: list[MetricSample] = await _scalars(
            session_factory,
            select(MetricSample).where(MetricSample.node_id == node_id, MetricSample.latency_ms.is_(None)),
        )
        assert len(gap) == expected.get(hostname, 0), hostname
        for sample in gap:
            assert sample.cpu_percent == 0.0
            assert sample.net_upload_kbps == 0.0
            assert sample.net_download_kbps == 0.0
            assert sample.process_count == 0
            assert sample.temperature_c is None


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


async def test_alerts_cover_every_anomaly_type_with_mixed_severity_and_acknowledgement(
    session_factory: SessionFactory,
) -> None:
    report = await seed.seed_database(session_factory, now=NOW)

    alerts: list[AnomalyAlert] = await _scalars(session_factory, select(AnomalyAlert))
    assert {alert.anomaly_type for alert in alerts} == set(AnomalyType)
    assert AnomalyType.SERVICE_DOWN in {alert.anomaly_type for alert in alerts}
    assert AnomalyType.THERMAL_SPIKE in {alert.anomaly_type for alert in alerts}
    assert {alert.severity for alert in alerts} >= {AlertSeverity.WARNING, AlertSeverity.CRITICAL}
    assert any(alert.acknowledged for alert in alerts)
    assert any(not alert.acknowledged for alert in alerts)
    assert report.alerts_inserted == len(alerts)

    ids = await _node_ids(session_factory)
    assert {alert.node_id for alert in alerts} == set(ids.values()), "every seeded node has at least one alert"

    window_start = NOW - timedelta(hours=24)
    for alert in alerts:
        detected_at = _utc(alert.detected_at)
        assert window_start <= detected_at <= NOW
        assert alert.message
        if alert.acknowledged:
            assert alert.acknowledged_at is not None
            assert detected_at <= _utc(alert.acknowledged_at) <= NOW
        else:
            assert alert.acknowledged_at is None


async def test_alerts_round_trip_through_the_api_schemas(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)

    async with session_factory() as session:
        total, rows = await crud.query_alerts(session, crud.AlertFilters(), limit=None)
    assert total == len(rows) == 16
    assert all(row.node_hostname in SIMULATED_HOSTNAMES for row in rows)
    AnomalyAlertCreate.model_validate(rows[0].model_dump())

    async with session_factory() as session:
        only_open = await crud.query_alerts(session, crud.AlertFilters(acknowledged=False), limit=None)
        by_type = await crud.query_alerts(
            session, crud.AlertFilters(anomaly_type=AnomalyType.SERVICE_DOWN), limit=None
        )
    assert 0 < only_open[0] < total
    assert by_type[0] == 2


async def test_each_alert_points_at_the_sample_that_triggered_it(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    ids = await _node_ids(session_factory)
    nodes: dict[int, Node] = {node.id: node for node in await _scalars(session_factory, select(Node))}
    samples_by_node: dict[int, dict[datetime, MetricSample]] = {}
    for node_id in ids.values():
        samples: list[MetricSample] = await _scalars(
            session_factory, select(MetricSample).where(MetricSample.node_id == node_id)
        )
        samples_by_node[node_id] = {_utc(sample.timestamp): sample for sample in samples}

    for alert in await _scalars(session_factory, select(AnomalyAlert)):
        sample = samples_by_node[alert.node_id][_utc(alert.detected_at)]
        kind = alert.anomaly_type
        if kind is AnomalyType.CPU_SPIKE:
            assert alert.observed_value == pytest.approx(sample.cpu_percent, abs=0.01)
        elif kind is AnomalyType.CRITICAL_LATENCY:
            assert alert.observed_value == pytest.approx(sample.latency_ms, abs=0.01)
        elif kind is AnomalyType.DISK_PRESSURE:
            assert alert.observed_value == pytest.approx(sample.disk_percent, abs=0.01)
        elif kind is AnomalyType.MEMORY_LEAK:
            assert alert.observed_value == pytest.approx(sample.memory_percent, abs=0.01)
        elif kind is AnomalyType.THERMAL_SPIKE:
            assert alert.observed_value == pytest.approx(sample.temperature_c, abs=0.01)
        elif kind is AnomalyType.SERVICE_DOWN:
            assert sample.latency_ms is None
        else:  # BANDWIDTH_SATURATION: busiest-direction link utilisation percent
            capacity_kbps = nodes[alert.node_id].link_capacity_mbps * 1000.0
            expected = 100.0 * max(sample.net_upload_kbps, sample.net_download_kbps) / capacity_kbps
            assert alert.observed_value == pytest.approx(expected, abs=0.01)


async def test_alert_severity_follows_the_detector_thresholds(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    settings = get_settings()

    for alert in await _scalars(session_factory, select(AnomalyAlert)):
        if alert.anomaly_type is AnomalyType.THERMAL_SPIKE:
            limit = (
                settings.anomaly_temperature_critical_c
                if alert.severity is AlertSeverity.CRITICAL
                else settings.anomaly_temperature_warning_c
            )
            assert alert.observed_value >= limit
            assert alert.threshold == limit
        if alert.anomaly_type is AnomalyType.CRITICAL_LATENCY and alert.severity is AlertSeverity.CRITICAL:
            assert alert.observed_value >= settings.anomaly_latency_critical_ms
        if alert.anomaly_type is AnomalyType.DISK_PRESSURE:
            assert alert.observed_value >= settings.anomaly_disk_critical_percent
        if alert.anomaly_type is AnomalyType.SERVICE_DOWN:
            assert alert.observed_value == settings.anomaly_service_down_samples


def test_seed_detector_constants_match_the_live_detector_and_simulator() -> None:
    assert seed._CPU_SUSTAINED_SAMPLES == anomaly_detector._CPU_SUSTAINED_SAMPLES
    assert seed._CPU_OUTLIER_PERSISTENCE_SAMPLES == anomaly_detector._CPU_OUTLIER_PERSISTENCE_SAMPLES
    assert seed._CPU_OUTLIER_MIN_PERCENT == anomaly_detector._CPU_MIN_ABSOLUTE_PERCENT
    assert seed._CPU_OUTLIER_MIN_RISE_POINTS == anomaly_detector._CPU_MIN_RISE_POINTS
    assert seed._MEMORY_CRITICAL_PERCENT == anomaly_detector._MEMORY_CRITICAL_PERCENT
    assert seed._BANDWIDTH_CRITICAL_PERCENT == anomaly_detector._BANDWIDTH_CRITICAL_PERCENT
    assert seed._NORMAL_NET_CEILING_FRACTION == telemetry_collector._NORMAL_NET_CEILING_FRACTION == 0.80
    assert seed._NORMAL_CPU_CEILING == telemetry_collector._NORMAL_CPU_CEILING
    assert seed.METRIC_NET_PEAK == anomaly_detector.METRIC_NET_PEAK == "net_peak_kbps"


def _incident_window(samples: list[MetricSample], plan: seed.IncidentPlan) -> list[MetricSample]:
    """The samples an incident plan reshaped: ``length`` samples from the first one at or after its onset."""
    onset = NOW - timedelta(hours=plan.hours_ago)
    ordered = sorted(samples, key=lambda sample: _utc(sample.timestamp))
    start = next(i for i, sample in enumerate(ordered) if _utc(sample.timestamp) >= onset)
    return ordered[start : start + plan.length]


async def test_bandwidth_alerts_use_the_busiest_direction_and_normal_traffic_stays_below_80_percent(
    session_factory: SessionFactory,
) -> None:
    await seed.seed_database(session_factory, now=NOW)
    settings = get_settings()
    nodes: dict[int, Node] = {node.id: node for node in await _scalars(session_factory, select(Node))}
    alerts: list[AnomalyAlert] = await _scalars(
        session_factory, select(AnomalyAlert).where(AnomalyAlert.anomaly_type == AnomalyType.BANDWIDTH_SATURATION)
    )
    plans = [plan for plan in seed.INCIDENT_PLANS if plan.kind is AnomalyType.BANDWIDTH_SATURATION]
    assert len(alerts) == len(plans) > 0
    assert {plan.severity for plan in plans} == {AlertSeverity.WARNING, AlertSeverity.CRITICAL}

    for alert in alerts:
        node = nodes[alert.node_id]
        capacity_kbps = node.link_capacity_mbps * 1000.0
        trigger: MetricSample = (
            await _scalars(
                session_factory,
                select(MetricSample).where(
                    MetricSample.node_id == alert.node_id, MetricSample.timestamp == alert.detected_at
                ),
            )
        )[0]
        busiest = max(trigger.net_upload_kbps, trigger.net_download_kbps)
        direction = "upload" if trigger.net_upload_kbps >= trigger.net_download_kbps else "download"

        assert alert.observed_value == pytest.approx(100.0 * busiest / capacity_kbps, abs=0.01)
        assert 85.0 <= alert.observed_value <= 99.0
        assert alert.metric_name == "net_utilization_percent"
        assert alert.threshold == settings.anomaly_bandwidth_saturation_percent
        expected_severity = AlertSeverity.CRITICAL if alert.observed_value >= 95.0 else AlertSeverity.WARNING
        assert alert.severity is expected_severity
        assert f"link at {alert.observed_value:.1f}%" in alert.message
        assert f"{busiest / 1000.0:.1f} Mbps {direction} of {node.link_capacity_mbps:g} Mbps" in alert.message
        assert alert.baseline_mean is not None and alert.baseline_mean <= 80.0

    for hostname, node_id in (await _node_ids(session_factory)).items():
        capacity_kbps = nodes[node_id].link_capacity_mbps * 1000.0
        samples: list[MetricSample] = await _scalars(
            session_factory, select(MetricSample).where(MetricSample.node_id == node_id)
        )
        incident_stamps = {
            sample.timestamp
            for plan in plans
            if plan.hostname == hostname
            for sample in _incident_window(samples, plan)
        }
        assert len(incident_stamps) == sum(plan.length for plan in plans if plan.hostname == hostname)
        for sample in samples:
            busiest = max(sample.net_upload_kbps, sample.net_download_kbps)
            if sample.timestamp in incident_stamps:
                assert busiest >= 0.85 * capacity_kbps, hostname
            else:
                assert busiest <= 0.80 * capacity_kbps * 1.0001, hostname


async def test_cpu_alerts_follow_the_sustained_and_persistent_outlier_rules(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    settings = get_settings()
    hostnames = {node_id: hostname for hostname, node_id in (await _node_ids(session_factory)).items()}
    alerts: list[AnomalyAlert] = await _scalars(
        session_factory, select(AnomalyAlert).where(AnomalyAlert.anomaly_type == AnomalyType.CPU_SPIKE)
    )
    plans = [plan for plan in seed.INCIDENT_PLANS if plan.kind is AnomalyType.CPU_SPIKE]
    assert len(alerts) == len(plans)
    assert {alert.severity for alert in alerts} == {AlertSeverity.WARNING, AlertSeverity.CRITICAL}

    for alert in alerts:
        host = hostnames[alert.node_id]
        plan = next(p for p in plans if p.hostname == host and p.severity is alert.severity)
        samples: list[MetricSample] = await _scalars(
            session_factory, select(MetricSample).where(MetricSample.node_id == alert.node_id)
        )
        window = _incident_window(samples, plan)
        if alert.severity is AlertSeverity.CRITICAL:
            trigger = window[2]
            assert alert.observed_value >= settings.anomaly_cpu_critical_percent >= 90.0
            assert all(sample.cpu_percent >= settings.anomaly_cpu_critical_percent for sample in window[:3])
            assert alert.threshold == settings.anomaly_cpu_critical_percent
            assert alert.message.startswith(f"Sustained critical CPU load on {host}: ")
            assert "(3 consecutive samples, limit 90%, baseline " in alert.message
        else:
            trigger = window[9]
            assert alert.observed_value < settings.anomaly_cpu_critical_percent
            assert alert.baseline_mean is not None and alert.z_score is not None
            assert alert.z_score >= settings.anomaly_zscore_threshold
            assert alert.threshold == settings.anomaly_zscore_threshold
            assert alert.message.startswith(f"CPU spike on {host}: ")
            assert "(10 consecutive samples above baseline, baseline " in alert.message
            floor = max(alert.baseline_mean + 20.0, 70.0)
            for sample in window[:10]:
                assert floor <= sample.cpu_percent < settings.anomaly_cpu_critical_percent
        assert _utc(alert.detected_at) == _utc(trigger.timestamp)
        assert alert.observed_value == pytest.approx(trigger.cpu_percent, abs=0.01)


async def test_thermal_alerts_use_the_detector_wording_and_limits(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    settings = get_settings()

    alerts: list[AnomalyAlert] = await _scalars(
        session_factory, select(AnomalyAlert).where(AnomalyAlert.anomaly_type == AnomalyType.THERMAL_SPIKE)
    )
    assert {alert.severity for alert in alerts} == {AlertSeverity.WARNING, AlertSeverity.CRITICAL}
    for alert in alerts:
        critical = alert.severity is AlertSeverity.CRITICAL
        limit = settings.anomaly_temperature_critical_c if critical else settings.anomaly_temperature_warning_c
        title = "Critical temperature" if critical else "High temperature"
        assert alert.message.startswith(f"{title} on ")
        assert f"{alert.observed_value:.1f}°C (limit {limit:.0f}°C, baseline " in alert.message
        assert alert.observed_value >= max(limit, 75.0)
        assert alert.baseline_mean is not None and alert.observed_value >= alert.baseline_mean + 5.0


# ---------------------------------------------------------------------------
# Port audits
# ---------------------------------------------------------------------------


async def _audits_by_hostname(factory: SessionFactory) -> dict[str, tuple[PortAudit, list[PortFinding]]]:
    ids = {node_id: hostname for hostname, node_id in (await _node_ids(factory)).items()}
    result: dict[str, tuple[PortAudit, list[PortFinding]]] = {}
    async with factory() as session:
        for audit in (await session.execute(select(PortAudit))).scalars():
            loaded = await crud.get_port_audit(session, audit.id)
            assert loaded is not None and audit.node_id is not None
            result[ids[audit.node_id]] = (loaded, list(loaded.findings))
    return result


async def test_each_node_gets_a_port_audit_with_scanner_classification(session_factory: SessionFactory) -> None:
    report = await seed.seed_database(session_factory, now=NOW)

    audits = await _audits_by_hostname(session_factory)
    assert sorted(audits) == SIMULATED_HOSTNAMES
    assert report.audits_inserted == 8
    assert report.findings_inserted == sum(len(findings) for _, findings in audits.values())

    for hostname, (audit, findings) in audits.items():
        assert audit.target_host == audit.resolved_ip
        assert audit.total_ports_scanned == len(COMMON_PORTS)
        assert audit.open_ports_count == len(findings) > 0
        assert audit.host_reachable is True
        assert _utc(audit.started_at) < _utc(audit.finished_at) <= NOW
        assert audit.risk_score == calculate_risk_score(finding.risk_level for finding in findings)
        assert all(finding.state is PortState.OPEN for finding in findings)
        for finding in findings:
            catalogued = COMMON_PORTS[finding.port]
            assert finding.service == catalogued.service
            # Banner rules may only raise the risk, never lower it below the catalogue.
            assert finding.risk_reason.startswith(catalogued.risk_reason), (hostname, finding.port)
            assert finding.recommendation.endswith(catalogued.recommendation), (hostname, finding.port)


async def test_vulnerable_services_are_critical_findings(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    audits = await _audits_by_hostname(session_factory)

    def critical_ports(hostname: str) -> set[int]:
        return {finding.port for finding in audits[hostname][1] if finding.risk_level is RiskLevel.CRITICAL}

    assert 23 in critical_ports("fw-core-01")
    assert {21, 445} <= critical_ports("nas-storage-01")
    assert {445, 3389} <= critical_ports("dc-ad-01")
    assert 6379 in critical_ports("cache-redis-01")
    db_ports = {finding.port: finding for finding in audits["db-primary-01"][1]}
    assert db_ports[5432].risk_level is RiskLevel.HIGH
    assert db_ports[5432].service == "postgresql"

    assert audits["fw-core-01"][0].overall_risk is RiskLevel.CRITICAL
    assert audits["nas-storage-01"][0].overall_risk is RiskLevel.CRITICAL
    assert audits["dc-ad-01"][0].overall_risk is RiskLevel.CRITICAL
    assert audits["cache-redis-01"][0].overall_risk is RiskLevel.CRITICAL
    assert any(audit.overall_risk is not RiskLevel.CRITICAL for audit, _ in audits.values())

    # FTP is only CRITICAL through the scanner's own banner rule (vsFTPd 2.3.4 backdoor).
    ftp = next(finding for finding in audits["nas-storage-01"][1] if finding.port == 21)
    assert COMMON_PORTS[21].risk_level is RiskLevel.HIGH
    assert ftp.banner is not None and "vsFTPd 2.3.4" in ftp.banner
    assert "CVE-2011-2523" in ftp.risk_reason

    # Normal services keep their real, lower risk.
    web = {finding.port: finding.risk_level for finding in audits["web-app-01"][1]}
    assert web[443] is RiskLevel.LOW
    assert web[22] is RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Idempotency and reset
# ---------------------------------------------------------------------------


async def test_second_run_inserts_nothing(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    before = await _table_counts(session_factory)

    again = await seed.seed_database(session_factory, now=NOW)

    assert await _table_counts(session_factory) == before
    assert again.total_inserted == 0
    assert again.nodes_created == 0
    assert sorted(again.skipped_metrics) == SIMULATED_HOSTNAMES
    assert sorted(again.skipped_alerts) == SIMULATED_HOSTNAMES
    assert sorted(again.skipped_audits) == SIMULATED_HOSTNAMES
    assert "Nothing to do" in "\n".join(again.lines())


async def test_second_run_later_in_time_still_inserts_nothing(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    before = await _table_counts(session_factory)

    again = await seed.seed_database(session_factory, now=NOW + timedelta(minutes=45))

    assert again.total_inserted == 0
    assert await _table_counts(session_factory) == before


async def test_missing_data_of_one_node_is_backfilled_without_touching_the_rest(
    session_factory: SessionFactory,
) -> None:
    await seed.seed_database(session_factory, now=NOW)
    before = await _table_counts(session_factory)
    victim = (await _node_ids(session_factory))["web-app-01"]
    async with session_factory() as session, session.begin():
        await session.execute(delete(MetricSample).where(MetricSample.node_id == victim))

    again = await seed.seed_database(session_factory, now=NOW)

    assert again.metrics_inserted == 200
    assert again.alerts_inserted == 0
    assert again.audits_inserted == 0
    assert "web-app-01" not in again.skipped_metrics
    assert len(again.skipped_metrics) == 7
    assert await _table_counts(session_factory) == before


async def test_fresh_live_rows_do_not_block_the_historical_backfill(session_factory: SessionFactory) -> None:
    await seed._ensure_schema(session_factory)
    async with session_factory() as session:
        ids = await crud.upsert_nodes(session, EnterpriseClusterSimulator(get_settings()).specs())
    async with session_factory() as session, session.begin():
        session.add(
            MetricSample(
                node_id=ids["db-primary-01"],
                timestamp=NOW - timedelta(seconds=30),
                cpu_percent=40.0,
                memory_percent=60.0,
                memory_used_mb=1000.0,
                disk_percent=50.0,
                latency_ms=1.0,
                net_upload_kbps=1.0,
                net_download_kbps=1.0,
                process_count=100,
                temperature_c=40.0,
            )
        )

    report = await seed.seed_database(session_factory, now=NOW)

    assert report.metrics_inserted == 1600
    assert report.nodes_created == 0
    assert await _count(session_factory, MetricSample, MetricSample.node_id == ids["db-primary-01"]) == 201


async def test_reset_reseeds_identical_data(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    before = await _table_counts(session_factory)
    first_cpu = sorted(
        (_utc(sample.timestamp), sample.node_id, sample.cpu_percent)
        for sample in await _scalars(session_factory, select(MetricSample))
    )

    report = await seed.seed_database(session_factory, reset=True, now=NOW)

    assert report.reset is True
    assert (report.deleted_metrics, report.deleted_alerts, report.deleted_audits) == (1600, 16, 8)
    assert report.deleted_findings == before["findings"]
    assert (report.metrics_inserted, report.alerts_inserted, report.audits_inserted) == (1600, 16, 8)
    assert await _table_counts(session_factory) == before
    second_cpu = sorted(
        (_utc(sample.timestamp), sample.node_id, sample.cpu_percent)
        for sample in await _scalars(session_factory, select(MetricSample))
    )
    assert second_cpu == first_cpu, "the default RNG seed must make seeding deterministic"
    assert any("Reset" in line for line in report.lines())


async def test_rng_seed_changes_the_generated_history(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW, rng_seed=1)
    first = sorted(sample.cpu_percent for sample in await _scalars(session_factory, select(MetricSample)))

    await seed.seed_database(session_factory, reset=True, now=NOW, rng_seed=2)
    second = sorted(sample.cpu_percent for sample in await _scalars(session_factory, select(MetricSample)))

    assert first != second
    assert len(first) == len(second) == 1600


async def test_reset_leaves_other_nodes_untouched(session_factory: SessionFactory) -> None:
    await seed.seed_database(session_factory, now=NOW)
    async with session_factory() as session, session.begin():
        other = Node(
            hostname="real-host-01",
            display_name="Real host",
            role=NodeRole.HOST,
            ip_address="192.168.1.10",
            os_name="Windows 11",
            location="Local workstation",
            is_simulated=False,
            cpu_cores=8,
            memory_total_mb=16384.0,
            disk_total_gb=512.0,
            link_capacity_mbps=1000.0,
        )
        session.add(other)
        await session.flush()
        other_id = other.id
        session.add_all(
            MetricSample(
                node_id=other_id,
                timestamp=NOW - timedelta(minutes=minute),
                cpu_percent=10.0,
                memory_percent=40.0,
                memory_used_mb=6000.0,
                disk_percent=50.0,
                latency_ms=12.0,
                net_upload_kbps=5.0,
                net_download_kbps=9.0,
                process_count=300,
                temperature_c=None,
            )
            for minute in (5, 90, 600)
        )
        session.add(
            AnomalyAlert(
                node_id=other_id,
                detected_at=NOW - timedelta(hours=6),
                anomaly_type=AnomalyType.CPU_SPIKE,
                severity=AlertSeverity.WARNING,
                metric_name="cpu_percent",
                observed_value=80.0,
                threshold=3.0,
                message="CPU spike on real-host-01",
            )
        )
        outcome_audit = PortAudit(
            node_id=other_id,
            target_host="192.168.1.10",
            resolved_ip="192.168.1.10",
            started_at=NOW - timedelta(hours=5),
            finished_at=NOW - timedelta(hours=5) + timedelta(seconds=1),
            duration_ms=1000.0,
            host_reachable=True,
            host_latency_ms=1.0,
            total_ports_scanned=44,
            open_ports_count=1,
            risk_score=5.0,
            overall_risk=RiskLevel.LOW,
            findings=[
                PortFinding(
                    port=443,
                    service="https",
                    state=PortState.OPEN,
                    risk_level=RiskLevel.LOW,
                    risk_reason="HTTPS is exposed.",
                    recommendation="Keep it patched.",
                )
            ],
        )
        unattached_audit = PortAudit(
            node_id=None,
            target_host="10.20.0.1",
            resolved_ip="10.20.0.1",
            started_at=NOW - timedelta(hours=4),
            finished_at=NOW - timedelta(hours=4) + timedelta(seconds=1),
            duration_ms=1000.0,
            host_reachable=True,
            host_latency_ms=1.0,
            total_ports_scanned=44,
            open_ports_count=0,
            risk_score=0.0,
            overall_risk=RiskLevel.INFO,
        )
        session.add_all([outcome_audit, unattached_audit])

    report = await seed.seed_database(session_factory, reset=True, now=NOW)

    assert report.deleted_metrics == 1600
    assert report.deleted_alerts == 16
    assert await _count(session_factory, MetricSample, MetricSample.node_id == other_id) == 3
    assert await _count(session_factory, AnomalyAlert, AnomalyAlert.node_id == other_id) == 1
    assert await _count(session_factory, PortAudit, PortAudit.node_id == other_id) == 1
    assert await _count(session_factory, PortAudit, PortAudit.node_id.is_(None)) == 1
    assert await _count(session_factory, PortFinding, PortFinding.port == 443) >= 1
    assert await _count(session_factory, Node) == 9
    assert report.nodes_created == 0


async def test_application_startup_upsert_creates_no_duplicates_after_seeding(
    session_factory: SessionFactory,
) -> None:
    await seed.seed_database(session_factory, now=NOW)
    ids_before = await _node_ids(session_factory)

    async with session_factory() as session:
        ids_after = await crud.upsert_nodes(session, EnterpriseClusterSimulator(get_settings()).specs())

    assert await _count(session_factory, Node) == 8
    assert ids_after == ids_before
    assert sorted(await _node_ids(session_factory)) == SIMULATED_HOSTNAMES


async def test_seeding_after_the_application_upserted_the_nodes_reuses_them(session_factory: SessionFactory) -> None:
    await seed._ensure_schema(session_factory)
    async with session_factory() as session:
        ids = await crud.upsert_nodes(session, EnterpriseClusterSimulator(get_settings()).specs())

    report = await seed.seed_database(session_factory, now=NOW)

    assert report.nodes_created == 0
    assert await _node_ids(session_factory) == ids


async def test_works_on_a_completely_empty_database(session_factory: SessionFactory) -> None:
    """No tables exist before the first run: the seeder must create the schema itself."""
    report = await seed.seed_database(session_factory, now=NOW)

    counts = await _table_counts(session_factory)
    assert counts["nodes"] == 8
    assert counts["metrics"] == report.metrics_inserted == 1600
    assert counts["alerts"] == report.alerts_inserted
    assert counts["audits"] == report.audits_inserted == 8
    assert counts["findings"] == report.findings_inserted > 0


# ---------------------------------------------------------------------------
# Plan validation and report formatting
# ---------------------------------------------------------------------------


async def test_unknown_node_in_the_plan_is_rejected(
    session_factory: SessionFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad_plan = seed.IncidentPlan("ghost-01", AnomalyType.CPU_SPIKE, AlertSeverity.CRITICAL, 5.0, 3, None)
    monkeypatch.setattr(seed, "INCIDENT_PLANS", (*seed.INCIDENT_PLANS, bad_plan))

    with pytest.raises(seed.SeedError, match="ghost-01"):
        await seed.seed_database(session_factory, now=NOW)


@pytest.mark.parametrize(
    ("plan", "message"),
    [
        (
            seed.IncidentPlan("web-app-01", AnomalyType.DISK_PRESSURE, AlertSeverity.WARNING, 5.0, 3, None),
            "cannot be seeded",
        ),
        (
            seed.IncidentPlan("web-app-01", AnomalyType.CPU_SPIKE, AlertSeverity.CRITICAL, 0.5, 3, None),
            "hours ago",
        ),
        (
            seed.IncidentPlan("web-app-01", AnomalyType.SERVICE_DOWN, AlertSeverity.CRITICAL, 5.0, 1, None),
            "at least",
        ),
        (
            seed.IncidentPlan("web-app-01", AnomalyType.CPU_SPIKE, AlertSeverity.WARNING, 5.0, 9, None),
            "at least 10 samples",
        ),
        (
            seed.IncidentPlan("web-app-01", AnomalyType.CPU_SPIKE, AlertSeverity.CRITICAL, 5.0, 2, None),
            "at least 3 samples",
        ),
    ],
)
async def test_inconsistent_incident_plans_are_rejected(
    session_factory: SessionFactory,
    monkeypatch: pytest.MonkeyPatch,
    plan: seed.IncidentPlan,
    message: str,
) -> None:
    monkeypatch.setattr(seed, "INCIDENT_PLANS", (plan,))

    with pytest.raises(seed.SeedError, match=message):
        await seed.seed_database(session_factory, now=NOW)


def test_report_summary_lists_every_table() -> None:
    report = seed.SeedReport(reset=False, window_start=NOW - timedelta(hours=24), window_end=NOW)
    report.metrics_inserted = 10
    text = "\n".join(report.lines())

    assert "Metrics" in text and "Alerts" in text and "Port audits" in text
    assert "Reset" not in text
    assert report.total_inserted == 10


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _hostname_filter() -> Any:
    return Node.hostname.in_(SIMULATED_HOSTNAMES)


async def _preexisting_seed_hostnames() -> set[str]:
    try:
        async with SessionLocal() as session:
            result = await session.execute(select(Node.hostname).where(_hostname_filter()))
            return set(result.scalars())
    except Exception:  # noqa: BLE001 - tables may not exist yet in a pristine test database
        return set()
    finally:
        await dispose_db()


async def _purge_default_database(preexisting: set[str]) -> int:
    """Remove what the CLI test seeded into the shared test database; returns the remaining node count."""
    try:
        async with SessionLocal() as session, session.begin():
            node_ids = select(Node.id).where(_hostname_filter())
            await session.execute(
                delete(PortFinding).where(
                    PortFinding.audit_id.in_(select(PortAudit.id).where(PortAudit.node_id.in_(node_ids)))
                )
            )
            await session.execute(delete(PortAudit).where(PortAudit.node_id.in_(node_ids)))
            await session.execute(delete(AnomalyAlert).where(AnomalyAlert.node_id.in_(node_ids)))
            await session.execute(delete(MetricSample).where(MetricSample.node_id.in_(node_ids)))
            created_by_test = set(SIMULATED_HOSTNAMES) - preexisting
            if created_by_test:
                await session.execute(delete(Node).where(Node.hostname.in_(created_by_test)))
        async with SessionLocal() as session:
            return int(await session.scalar(select(func.count(Node.id))) or 0)
    finally:
        await dispose_db()


async def _default_database_counts() -> dict[str, int]:
    try:
        async with SessionLocal() as session:
            node_ids = select(Node.id).where(_hostname_filter())
            return {
                "metrics": int(
                    await session.scalar(select(func.count(MetricSample.id)).where(MetricSample.node_id.in_(node_ids)))
                    or 0
                ),
                "alerts": int(
                    await session.scalar(select(func.count(AnomalyAlert.id)).where(AnomalyAlert.node_id.in_(node_ids)))
                    or 0
                ),
                "audits": int(
                    await session.scalar(select(func.count(PortAudit.id)).where(PortAudit.node_id.in_(node_ids))) or 0
                ),
            }
    finally:
        await dispose_db()


def test_cli_seeds_the_configured_database_and_second_run_is_a_no_op(capsys: pytest.CaptureFixture[str]) -> None:
    preexisting = asyncio.run(_preexisting_seed_hostnames())
    try:
        assert seed.main(["--reset"]) == 0
        first = capsys.readouterr().out
        assert "Metrics      : 1600 inserted" in first
        assert "Alerts       : 16 inserted" in first
        assert "Port audits  : 8 inserted" in first
        assert asyncio.run(_default_database_counts()) == {"metrics": 1600, "alerts": 16, "audits": 8}

        assert seed.main([]) == 0
        second = capsys.readouterr().out
        assert "Metrics      : 0 inserted, 8 node(s) skipped" in second
        assert "Nothing to do" in second
        assert asyncio.run(_default_database_counts()) == {"metrics": 1600, "alerts": 16, "audits": 8}
    finally:
        asyncio.run(_purge_default_database(preexisting))


def test_cli_returns_a_non_zero_exit_code_on_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def failing_seed(*_args: Any, **_kwargs: Any) -> seed.SeedReport:
        raise seed.SeedError("boom")

    monkeypatch.setattr(seed, "seed_database", failing_seed)

    assert seed.main([]) == 1
    assert capsys.readouterr().out == ""


def test_cli_parses_its_flags() -> None:
    args = seed._parse_args(["--reset", "--rng-seed", "42"])
    assert args.reset is True
    assert args.rng_seed == 42
    defaults = seed._parse_args([])
    assert defaults.reset is False
    assert defaults.rng_seed == seed.DEFAULT_RNG_SEED


def test_default_incident_plan_covers_every_anomaly_type_and_node() -> None:
    kinds: Counter[AnomalyType] = Counter(plan.kind for plan in seed.INCIDENT_PLANS)
    assert set(kinds) == set(AnomalyType)
    assert {plan.hostname for plan in seed.INCIDENT_PLANS} == set(SIMULATED_HOSTNAMES)
