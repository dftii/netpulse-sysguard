"""Data-access layer: every SQL query used by the API and the telemetry pipeline."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.enums import AlertSeverity, AnomalyType, NodeStatus
from app.models import AnomalyAlert, MetricSample, Node, PortAudit, PortFinding
from app.schemas import AnomalyAlertRead, NodeCreate, NodeTelemetry, PortScanOutcome


def to_utc(value: datetime) -> datetime:
    """Normalise user-supplied datetimes: naive values are interpreted as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


async def upsert_nodes(session: AsyncSession, specs: Sequence[NodeCreate]) -> dict[str, int]:
    """Insert new nodes and refresh the static attributes of existing ones. Returns hostname -> id."""
    hostnames = [spec.hostname for spec in specs]
    result = await session.execute(select(Node).where(Node.hostname.in_(hostnames)))
    existing = {node.hostname: node for node in result.scalars()}

    for spec in specs:
        node = existing.get(spec.hostname)
        if node is None:
            node = Node(**spec.model_dump(), status=NodeStatus.ONLINE)
            session.add(node)
            existing[spec.hostname] = node
        else:
            for field, value in spec.model_dump().items():
                setattr(node, field, value)

    await session.commit()
    return {hostname: node.id for hostname, node in existing.items()}


async def list_nodes(session: AsyncSession) -> list[Node]:
    result = await session.execute(select(Node).order_by(Node.is_simulated, Node.id))
    return list(result.scalars())


async def get_node(session: AsyncSession, node_id: int) -> Node | None:
    return await session.get(Node, node_id)


async def mark_nodes_offline(session: AsyncSession, hostnames_alive: Sequence[str]) -> None:
    """Flag every node that is not produced by the current collector as offline (e.g. simulator disabled)."""
    await session.execute(
        update(Node).where(Node.hostname.not_in(list(hostnames_alive))).values(status=NodeStatus.OFFLINE)
    )
    await session.commit()


# ---------------------------------------------------------------------------
# Telemetry ingestion
# ---------------------------------------------------------------------------


async def record_tick(
    session: AsyncSession,
    samples: Sequence[NodeTelemetry],
    *,
    persist_metrics: bool,
) -> None:
    """Update live node status/last_seen and, when requested, store the historical metric samples."""
    for sample in samples:
        await session.execute(
            update(Node)
            .where(Node.id == sample.node_id)
            .values(status=sample.status, last_seen_at=sample.timestamp)
        )
        if persist_metrics:
            session.add(
                MetricSample(
                    node_id=sample.node_id,
                    timestamp=sample.timestamp,
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
            )
    await session.commit()


async def list_metrics(
    session: AsyncSession,
    node_id: int,
    *,
    since: datetime,
    until: datetime | None = None,
    limit: int,
) -> list[MetricSample]:
    """Return the most recent `limit` samples inside the window, in chronological order."""
    statement = select(MetricSample).where(
        MetricSample.node_id == node_id, MetricSample.timestamp >= to_utc(since)
    )
    if until is not None:
        statement = statement.where(MetricSample.timestamp <= to_utc(until))
    statement = statement.order_by(MetricSample.timestamp.desc()).limit(limit)
    result = await session.execute(statement)
    return list(reversed(result.scalars().all()))


async def purge_metrics_older_than(session: AsyncSession, cutoff: datetime) -> int:
    result = await session.execute(delete(MetricSample).where(MetricSample.timestamp < to_utc(cutoff)))
    await session.commit()
    return int(result.rowcount or 0)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AlertFilters:
    node_id: int | None = None
    severity: AlertSeverity | None = None
    anomaly_type: AnomalyType | None = None
    acknowledged: bool | None = None
    since: datetime | None = None
    until: datetime | None = None

    def as_dict(self) -> dict[str, str | int | bool | None]:
        return {
            "node_id": self.node_id,
            "severity": self.severity.value if self.severity else None,
            "anomaly_type": self.anomaly_type.value if self.anomaly_type else None,
            "acknowledged": self.acknowledged,
            "since": to_utc(self.since).isoformat() if self.since else None,
            "until": to_utc(self.until).isoformat() if self.until else None,
        }


def alert_to_read(alert: AnomalyAlert, hostname: str | None) -> AnomalyAlertRead:
    return AnomalyAlertRead.model_validate(alert).model_copy(update={"node_hostname": hostname})


async def query_alerts(
    session: AsyncSession,
    filters: AlertFilters,
    *,
    limit: int | None,
    offset: int = 0,
) -> tuple[int, list[AnomalyAlertRead]]:
    """Filtered, newest-first alert listing. `limit=None` returns every match (used by exports)."""
    conditions = []
    if filters.node_id is not None:
        conditions.append(AnomalyAlert.node_id == filters.node_id)
    if filters.severity is not None:
        conditions.append(AnomalyAlert.severity == filters.severity)
    if filters.anomaly_type is not None:
        conditions.append(AnomalyAlert.anomaly_type == filters.anomaly_type)
    if filters.acknowledged is not None:
        conditions.append(AnomalyAlert.acknowledged == filters.acknowledged)
    if filters.since is not None:
        conditions.append(AnomalyAlert.detected_at >= to_utc(filters.since))
    if filters.until is not None:
        conditions.append(AnomalyAlert.detected_at <= to_utc(filters.until))

    total = await session.scalar(select(func.count(AnomalyAlert.id)).where(*conditions)) or 0

    statement = (
        select(AnomalyAlert, Node.hostname)
        .join(Node, Node.id == AnomalyAlert.node_id)
        .where(*conditions)
        .order_by(AnomalyAlert.detected_at.desc(), AnomalyAlert.id.desc())
        .offset(offset)
    )
    if limit is not None:
        statement = statement.limit(limit)
    rows = await session.execute(statement)
    return int(total), [alert_to_read(alert, hostname) for alert, hostname in rows.all()]


async def count_unacknowledged_alerts(session: AsyncSession) -> int:
    return int(
        await session.scalar(select(func.count(AnomalyAlert.id)).where(AnomalyAlert.acknowledged.is_(False)))
        or 0
    )


async def acknowledge_alert(session: AsyncSession, alert_id: int) -> AnomalyAlertRead | None:
    alert = await session.get(AnomalyAlert, alert_id)
    if alert is None:
        return None
    if not alert.acknowledged:
        alert.acknowledged = True
        alert.acknowledged_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(alert)
    hostname = await session.scalar(select(Node.hostname).where(Node.id == alert.node_id))
    return alert_to_read(alert, hostname)


# ---------------------------------------------------------------------------
# Port audits
# ---------------------------------------------------------------------------


async def save_port_audit(session: AsyncSession, outcome: PortScanOutcome, node_id: int | None) -> PortAudit:
    audit = PortAudit(
        node_id=node_id,
        target_host=outcome.target_host,
        resolved_ip=outcome.resolved_ip,
        started_at=outcome.started_at,
        finished_at=outcome.finished_at,
        duration_ms=outcome.duration_ms,
        host_reachable=outcome.host_reachable,
        host_latency_ms=outcome.host_latency_ms,
        total_ports_scanned=outcome.total_ports_scanned,
        open_ports_count=outcome.open_ports_count,
        risk_score=outcome.risk_score,
        overall_risk=outcome.overall_risk,
        findings=[PortFinding(**finding.model_dump()) for finding in outcome.findings],
    )
    session.add(audit)
    await session.commit()
    loaded = await get_port_audit(session, audit.id)
    if loaded is None:
        raise RuntimeError(f"Port audit {audit.id} vanished right after being committed")
    return loaded


async def get_port_audit(session: AsyncSession, audit_id: int) -> PortAudit | None:
    result = await session.execute(
        select(PortAudit)
        .options(selectinload(PortAudit.findings))
        .where(PortAudit.id == audit_id)
        .execution_options(populate_existing=True)
    )
    return result.scalar_one_or_none()


async def list_port_audits(
    session: AsyncSession, *, target: str | None, limit: int, offset: int
) -> list[PortAudit]:
    statement = select(PortAudit).order_by(PortAudit.started_at.desc(), PortAudit.id.desc())
    if target:
        statement = statement.where(PortAudit.target_host == target)
    result = await session.execute(statement.offset(offset).limit(limit))
    return list(result.scalars())
