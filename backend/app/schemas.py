"""Pydantic v2 schemas for the REST API, the WebSocket stream and inter-service contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from app.enums import AlertSeverity, AnomalyType, NodeRole, NodeStatus, PortState, RiskLevel


def _as_utc(value: datetime) -> datetime:
    """SQLite drops tzinfo; re-attach UTC so every timestamp is serialised as ISO-8601 with offset."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


UTCDateTime = Annotated[datetime, AfterValidator(_as_utc)]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class NodeBase(BaseModel):
    hostname: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=128)
    role: NodeRole
    ip_address: str = Field(max_length=45)
    os_name: str = Field(max_length=128)
    location: str = Field(default="", max_length=128)
    is_simulated: bool = False
    cpu_cores: int = Field(ge=1)
    memory_total_mb: float = Field(gt=0)
    disk_total_gb: float = Field(gt=0)
    link_capacity_mbps: float = Field(gt=0)


class NodeCreate(NodeBase):
    """Static description of a node, produced by the telemetry collector at startup."""


class NodeRead(NodeBase, ORMModel):
    id: int
    status: NodeStatus
    created_at: UTCDateTime
    last_seen_at: UTCDateTime | None = None


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


class MetricValues(BaseModel):
    cpu_percent: float = Field(ge=0, le=100)
    memory_percent: float = Field(ge=0, le=100)
    memory_used_mb: float = Field(ge=0)
    disk_percent: float = Field(ge=0, le=100)
    latency_ms: float | None = Field(default=None, ge=0)
    net_upload_kbps: float = Field(ge=0)
    net_download_kbps: float = Field(ge=0)
    process_count: int = Field(default=0, ge=0)
    temperature_c: float | None = None


class MetricSampleRead(MetricValues, ORMModel):
    id: int
    node_id: int
    timestamp: UTCDateTime


class NodeTelemetry(MetricValues):
    """Live snapshot of one node, emitted every tick by the TelemetryCollector and streamed over WebSocket."""

    node_id: int
    hostname: str
    display_name: str
    role: NodeRole
    ip_address: str
    is_simulated: bool
    status: NodeStatus
    timestamp: UTCDateTime
    memory_total_mb: float = Field(gt=0)
    link_capacity_mbps: float = Field(gt=0)
    uptime_seconds: float = Field(ge=0)
    simulated_incident: AnomalyType | None = None


class ClusterSummary(BaseModel):
    total_nodes: int
    online: int
    warning: int
    critical: int
    offline: int
    avg_cpu_percent: float
    avg_memory_percent: float
    total_upload_kbps: float
    total_download_kbps: float
    unacknowledged_alerts: int


# ---------------------------------------------------------------------------
# Anomaly alerts
# ---------------------------------------------------------------------------


class AnomalyAlertCreate(BaseModel):
    node_id: int
    detected_at: UTCDateTime
    anomaly_type: AnomalyType
    severity: AlertSeverity
    metric_name: str = Field(max_length=64)
    observed_value: float
    baseline_mean: float | None = None
    baseline_std: float | None = None
    z_score: float | None = None
    threshold: float
    message: str


class AnomalyAlertRead(AnomalyAlertCreate, ORMModel):
    id: int
    acknowledged: bool
    acknowledged_at: UTCDateTime | None = None
    node_hostname: str | None = None


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AnomalyAlertRead]


# ---------------------------------------------------------------------------
# Port audits
# ---------------------------------------------------------------------------


class PortScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255, examples=["127.0.0.1", "192.168.1.1"])
    ports: list[int] | None = Field(
        default=None,
        description="Explicit TCP ports to audit. Omit to audit the built-in catalogue of common services.",
    )
    port_range: tuple[int, int] | None = Field(
        default=None,
        description="Inclusive [start, end] range, merged with `ports`.",
    )
    timeout_seconds: float | None = Field(default=None, gt=0, le=10)
    concurrency: int | None = Field(default=None, ge=1, le=2000)
    grab_banners: bool | None = None
    node_id: int | None = Field(default=None, description="Optional node this audit is associated with.")

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return None
        for port in value:
            if not 1 <= port <= 65535:
                raise ValueError(f"Port {port} is outside the valid range 1-65535")
        return sorted(set(value))

    @field_validator("port_range")
    @classmethod
    def _validate_range(cls, value: tuple[int, int] | None) -> tuple[int, int] | None:
        if value is None:
            return None
        start, end = value
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError("port_range must satisfy 1 <= start <= end <= 65535")
        return value

    def resolved_ports(self) -> list[int] | None:
        """Merge `ports` and `port_range`; None means 'use the default catalogue'."""
        if self.ports is None and self.port_range is None:
            return None
        merged: set[int] = set(self.ports or [])
        if self.port_range is not None:
            merged.update(range(self.port_range[0], self.port_range[1] + 1))
        return sorted(merged)


class PortFindingResult(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp"] = "tcp"
    service: str
    state: PortState
    banner: str | None = None
    response_ms: float | None = None
    risk_level: RiskLevel
    risk_reason: str
    recommendation: str


class PortFindingRead(PortFindingResult, ORMModel):
    id: int
    audit_id: int


class PortScanOutcome(BaseModel):
    """Pure result returned by NetworkScanner.scan(), before persistence."""

    target_host: str
    resolved_ip: str
    started_at: UTCDateTime
    finished_at: UTCDateTime
    duration_ms: float
    host_reachable: bool
    host_latency_ms: float | None
    total_ports_scanned: int
    open_ports_count: int
    risk_score: float = Field(ge=0, le=100)
    overall_risk: RiskLevel
    findings: list[PortFindingResult]


class PortAuditSummary(ORMModel):
    id: int
    node_id: int | None
    target_host: str
    resolved_ip: str
    started_at: UTCDateTime
    finished_at: UTCDateTime
    duration_ms: float
    host_reachable: bool
    host_latency_ms: float | None
    total_ports_scanned: int
    open_ports_count: int
    risk_score: float
    overall_risk: RiskLevel


class PortAuditRead(PortAuditSummary):
    findings: list[PortFindingRead]


# ---------------------------------------------------------------------------
# Simulation control, streaming envelopes and service health
# ---------------------------------------------------------------------------


class IncidentInjectionRequest(BaseModel):
    hostname: str
    anomaly_type: AnomalyType
    duration_seconds: int = Field(default=60, ge=5, le=1800)


class IncidentInjectionResponse(BaseModel):
    hostname: str
    anomaly_type: AnomalyType
    duration_seconds: int
    accepted: bool


class TelemetryBroadcast(BaseModel):
    type: Literal["telemetry"] = "telemetry"
    timestamp: UTCDateTime
    tick: int
    summary: ClusterSummary
    nodes: list[NodeTelemetry]
    new_alerts: list[AnomalyAlertRead]


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    app_name: str
    version: str
    environment: str
    uptime_seconds: float
    telemetry_ticks: int
    websocket_clients: int
    database: Literal["ok", "error"]
