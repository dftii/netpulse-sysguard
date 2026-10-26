"""SQLAlchemy 2.0 ORM models: monitored nodes, historical metrics, port audits and anomaly alerts."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.enums import AlertSeverity, AnomalyType, NodeRole, NodeStatus, PortState, RiskLevel


def utcnow() -> datetime:
    return datetime.now(UTC)


def _enum(enum_cls: type) -> Enum:
    """Store enums as portable VARCHAR values instead of native DB enums."""
    return Enum(
        enum_cls,
        native_enum=False,
        validate_strings=True,
        length=32,
        values_callable=lambda members: [member.value for member in members],
    )


class Node(Base):
    """A monitored server: the real host machine or a simulated enterprise node."""

    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    role: Mapped[NodeRole] = mapped_column(_enum(NodeRole), index=True)
    ip_address: Mapped[str] = mapped_column(String(45))
    os_name: Mapped[str] = mapped_column(String(128))
    location: Mapped[str] = mapped_column(String(128), default="")
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    cpu_cores: Mapped[int] = mapped_column(Integer)
    memory_total_mb: Mapped[float] = mapped_column(Float)
    disk_total_gb: Mapped[float] = mapped_column(Float)
    link_capacity_mbps: Mapped[float] = mapped_column(Float)
    status: Mapped[NodeStatus] = mapped_column(_enum(NodeStatus), default=NodeStatus.ONLINE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    metrics: Mapped[list[MetricSample]] = relationship(
        back_populates="node", cascade="all, delete-orphan", passive_deletes=True
    )
    alerts: Mapped[list[AnomalyAlert]] = relationship(
        back_populates="node", cascade="all, delete-orphan", passive_deletes=True
    )
    port_audits: Mapped[list[PortAudit]] = relationship(back_populates="node")


class MetricSample(Base):
    """Point-in-time telemetry snapshot of a node."""

    __tablename__ = "metric_samples"
    __table_args__ = (Index("ix_metric_samples_node_time", "node_id", "timestamp"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    cpu_percent: Mapped[float] = mapped_column(Float)
    memory_percent: Mapped[float] = mapped_column(Float)
    memory_used_mb: Mapped[float] = mapped_column(Float)
    disk_percent: Mapped[float] = mapped_column(Float)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_upload_kbps: Mapped[float] = mapped_column(Float)
    net_download_kbps: Mapped[float] = mapped_column(Float)
    process_count: Mapped[int] = mapped_column(Integer, default=0)
    temperature_c: Mapped[float | None] = mapped_column(Float, nullable=True)

    node: Mapped[Node] = relationship(back_populates="metrics")


class PortAudit(Base):
    """Result header of a TCP port audit against one target host."""

    __tablename__ = "port_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True)
    target_host: Mapped[str] = mapped_column(String(255), index=True)
    resolved_ip: Mapped[str] = mapped_column(String(45))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[float] = mapped_column(Float)
    host_reachable: Mapped[bool] = mapped_column(Boolean)
    host_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_ports_scanned: Mapped[int] = mapped_column(Integer)
    open_ports_count: Mapped[int] = mapped_column(Integer)
    risk_score: Mapped[float] = mapped_column(Float)
    overall_risk: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel))

    node: Mapped[Node | None] = relationship(back_populates="port_audits")
    findings: Mapped[list[PortFinding]] = relationship(
        back_populates="audit",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="PortFinding.port",
    )


class PortFinding(Base):
    """A single port result inside a PortAudit. Only open ports are persisted."""

    __tablename__ = "port_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("port_audits.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    service: Mapped[str] = mapped_column(String(64))
    state: Mapped[PortState] = mapped_column(_enum(PortState))
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel))
    risk_reason: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)

    audit: Mapped[PortAudit] = relationship(back_populates="findings")


class AnomalyAlert(Base):
    """An incident raised by the anomaly detection engine."""

    __tablename__ = "anomaly_alerts"
    __table_args__ = (Index("ix_anomaly_alerts_node_time", "node_id", "detected_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    anomaly_type: Mapped[AnomalyType] = mapped_column(_enum(AnomalyType), index=True)
    severity: Mapped[AlertSeverity] = mapped_column(_enum(AlertSeverity), index=True)
    metric_name: Mapped[str] = mapped_column(String(64))
    observed_value: Mapped[float] = mapped_column(Float)
    baseline_mean: Mapped[float | None] = mapped_column(Float, nullable=True)
    baseline_std: Mapped[float | None] = mapped_column(Float, nullable=True)
    z_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    threshold: Mapped[float] = mapped_column(Float)
    message: Mapped[str] = mapped_column(Text)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    node: Mapped[Node] = relationship(back_populates="alerts")
