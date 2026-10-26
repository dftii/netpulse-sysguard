"""Pure serialisers that turn NetPulse domain objects into JSON and CSV export documents.

The functions in this module never touch the database, the filesystem or the wall clock.
Callers pass ``generated_at`` explicitly, which keeps the output deterministic and testable.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any

from app.enums import AlertSeverity, AnomalyType, ExportFormat, PortState, RiskLevel
from app.schemas import (
    AnomalyAlertRead,
    MetricSampleRead,
    NodeRead,
    PortAuditRead,
    PortFindingRead,
)

GENERATOR_NAME = "NetPulse SysGuard"

ALERT_CSV_COLUMNS: tuple[str, ...] = (
    "id",
    "detected_at",
    "node_id",
    "node_hostname",
    "anomaly_type",
    "severity",
    "metric_name",
    "observed_value",
    "baseline_mean",
    "baseline_std",
    "z_score",
    "threshold",
    "acknowledged",
    "acknowledged_at",
    "message",
)

METRIC_CSV_COLUMNS: tuple[str, ...] = (
    "node_id",
    "hostname",
    "sample_id",
    "timestamp",
    "cpu_percent",
    "memory_percent",
    "memory_used_mb",
    "disk_percent",
    "latency_ms",
    "net_upload_kbps",
    "net_download_kbps",
    "process_count",
    "temperature_c",
)

AUDIT_CSV_COLUMNS: tuple[str, ...] = (
    "audit_id",
    "node_id",
    "target_host",
    "resolved_ip",
    "started_at",
    "overall_risk",
    "risk_score",
    "finding_id",
    "port",
    "protocol",
    "service",
    "state",
    "risk_level",
    "risk_reason",
    "recommendation",
    "response_ms",
    "banner",
)

_STAT_DECIMALS = 3
_FILENAME_PREFIX_PATTERN = re.compile(r"[A-Za-z0-9_-]+")
_FILENAME_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _to_utc(value: datetime) -> datetime:
    """Treat naive datetimes as UTC and convert aware datetimes to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _iso_utc(value: datetime) -> str:
    """ISO-8601 UTC timestamp using the 'Z' suffix, matching Pydantic's JSON output."""
    return _to_utc(value).isoformat().replace("+00:00", "Z")


def _enum_text(value: Enum | str) -> str:
    """Return the wire value of an enum member (or the string itself)."""
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def _json_default(value: object) -> object:
    """Fallback encoder for values the json module cannot serialise natively."""
    if isinstance(value, datetime):
        return _iso_utc(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serialisable")


def _dump_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default)


def _csv_cell(value: object) -> str:
    """Render one value as CSV text: None becomes empty, datetimes ISO-8601 UTC, booleans lowercase."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return _iso_utc(value)
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def _render_csv(columns: Sequence[str], rows: Iterable[dict[str, object]]) -> str:
    """Render rows as CSV with an explicit header order and "\\n" line endings."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_csv_cell(row[column]) for column in columns])
    return buffer.getvalue()


def _report_header(title: str, generated_at: datetime) -> dict[str, Any]:
    return {
        "title": title,
        "generator": GENERATOR_NAME,
        "generated_at": _iso_utc(generated_at),
    }


def _stats(values: Sequence[float]) -> dict[str, float | None]:
    """Min, max and average rounded for display; all None when there is no data."""
    if not values:
        return {"min": None, "max": None, "avg": None}
    return {
        "min": round(min(values), _STAT_DECIMALS),
        "max": round(max(values), _STAT_DECIMALS),
        "avg": round(sum(values) / len(values), _STAT_DECIMALS),
    }


# ---------------------------------------------------------------------------
# Anomaly alerts
# ---------------------------------------------------------------------------


def _alert_node_key(alert: AnomalyAlertRead) -> str:
    return alert.node_hostname or f"node_{alert.node_id}"


def _alert_summary(alerts: Sequence[AnomalyAlertRead]) -> dict[str, Any]:
    severity_counts = Counter(_enum_text(alert.severity) for alert in alerts)
    type_counts = Counter(_enum_text(alert.anomaly_type) for alert in alerts)
    node_counts = Counter(_alert_node_key(alert) for alert in alerts)
    return {
        "total": len(alerts),
        "by_severity": {
            member.value: severity_counts.get(member.value, 0) for member in AlertSeverity
        },
        "by_type": {member.value: type_counts.get(member.value, 0) for member in AnomalyType},
        "by_node": dict(sorted(node_counts.items())),
    }


def _alert_row(alert: AnomalyAlertRead) -> dict[str, object]:
    return {
        "id": alert.id,
        "detected_at": alert.detected_at,
        "node_id": alert.node_id,
        "node_hostname": alert.node_hostname,
        "anomaly_type": alert.anomaly_type,
        "severity": alert.severity,
        "metric_name": alert.metric_name,
        "observed_value": alert.observed_value,
        "baseline_mean": alert.baseline_mean,
        "baseline_std": alert.baseline_std,
        "z_score": alert.z_score,
        "threshold": alert.threshold,
        "acknowledged": alert.acknowledged,
        "acknowledged_at": alert.acknowledged_at,
        "message": alert.message,
    }


def alerts_to_json(
    alerts: Sequence[AnomalyAlertRead],
    *,
    generated_at: datetime,
    filters: dict[str, Any],
) -> str:
    """Serialise anomaly alerts into a JSON report with metadata, a summary and the items."""
    payload: dict[str, Any] = {
        "report": {
            **_report_header("NetPulse SysGuard - Anomaly Incident Report", generated_at),
            "filters": filters,
        },
        "summary": _alert_summary(alerts),
        "items": [alert.model_dump(mode="json") for alert in alerts],
    }
    return _dump_json(payload)


def alerts_to_csv(alerts: Sequence[AnomalyAlertRead]) -> str:
    """Serialise anomaly alerts as CSV, one row per alert."""
    return _render_csv(ALERT_CSV_COLUMNS, (_alert_row(alert) for alert in alerts))


# ---------------------------------------------------------------------------
# Node metrics
# ---------------------------------------------------------------------------


def _metric_summary(samples: Sequence[MetricSampleRead]) -> dict[str, Any]:
    latencies = [sample.latency_ms for sample in samples if sample.latency_ms is not None]
    return {
        "sample_count": len(samples),
        "cpu_percent": _stats([sample.cpu_percent for sample in samples]),
        "memory_percent": _stats([sample.memory_percent for sample in samples]),
        "disk_percent": _stats([sample.disk_percent for sample in samples]),
        "latency_ms": _stats(latencies),
        "net_upload_kbps": _stats([sample.net_upload_kbps for sample in samples]),
        "net_download_kbps": _stats([sample.net_download_kbps for sample in samples]),
    }


def _metric_row(node: NodeRead, sample: MetricSampleRead) -> dict[str, object]:
    return {
        "node_id": node.id,
        "hostname": node.hostname,
        "sample_id": sample.id,
        "timestamp": sample.timestamp,
        "cpu_percent": sample.cpu_percent,
        "memory_percent": sample.memory_percent,
        "memory_used_mb": sample.memory_used_mb,
        "disk_percent": sample.disk_percent,
        "latency_ms": sample.latency_ms,
        "net_upload_kbps": sample.net_upload_kbps,
        "net_download_kbps": sample.net_download_kbps,
        "process_count": sample.process_count,
        "temperature_c": sample.temperature_c,
    }


def metrics_to_json(
    node: NodeRead,
    samples: Sequence[MetricSampleRead],
    *,
    generated_at: datetime,
    window_hours: float,
) -> str:
    """Serialise a node's metric samples into a JSON report with per-metric statistics."""
    payload: dict[str, Any] = {
        "report": {
            **_report_header("NetPulse SysGuard - Node Metrics Report", generated_at),
            "window_hours": window_hours,
        },
        "node": node.model_dump(mode="json"),
        "summary": _metric_summary(samples),
        "samples": [sample.model_dump(mode="json") for sample in samples],
    }
    return _dump_json(payload)


def metrics_to_csv(node: NodeRead, samples: Sequence[MetricSampleRead]) -> str:
    """Serialise a node's metric samples as CSV, one row per sample, prefixed with the node identity."""
    return _render_csv(
        METRIC_CSV_COLUMNS,
        (_metric_row(node, sample) for sample in samples),
    )


# ---------------------------------------------------------------------------
# Port audits
# ---------------------------------------------------------------------------


def _audit_summary(audit: PortAuditRead) -> dict[str, Any]:
    level_counts = Counter(_enum_text(finding.risk_level) for finding in audit.findings)
    open_port_numbers = sorted(
        finding.port for finding in audit.findings if finding.state == PortState.OPEN
    )
    return {
        "open_ports": audit.open_ports_count,
        "open_port_numbers": open_port_numbers,
        "total_ports_scanned": audit.total_ports_scanned,
        "risk_score": audit.risk_score,
        "overall_risk": _enum_text(audit.overall_risk),
        "findings_total": len(audit.findings),
        "counts_by_risk_level": {
            member.value: level_counts.get(member.value, 0) for member in RiskLevel
        },
    }


def _audit_row(audit: PortAuditRead, finding: PortFindingRead) -> dict[str, object]:
    return {
        "audit_id": audit.id,
        "node_id": audit.node_id,
        "target_host": audit.target_host,
        "resolved_ip": audit.resolved_ip,
        "started_at": audit.started_at,
        "overall_risk": audit.overall_risk,
        "risk_score": audit.risk_score,
        "finding_id": finding.id,
        "port": finding.port,
        "protocol": finding.protocol,
        "service": finding.service,
        "state": finding.state,
        "risk_level": finding.risk_level,
        "risk_reason": finding.risk_reason,
        "recommendation": finding.recommendation,
        "response_ms": finding.response_ms,
        "banner": finding.banner,
    }


def audit_to_json(audit: PortAuditRead, *, generated_at: datetime) -> str:
    """Serialise a port audit into a JSON report with audit metadata, a summary and the findings."""
    payload: dict[str, Any] = {
        "report": _report_header("NetPulse SysGuard - Port Audit Report", generated_at),
        "audit": audit.model_dump(mode="json", exclude={"findings"}),
        "summary": _audit_summary(audit),
        "findings": [finding.model_dump(mode="json") for finding in audit.findings],
    }
    return _dump_json(payload)


def audit_to_csv(audit: PortAuditRead) -> str:
    """Serialise a port audit as CSV, one row per finding, repeating the audit target columns."""
    return _render_csv(
        AUDIT_CSV_COLUMNS,
        (_audit_row(audit, finding) for finding in audit.findings),
    )


# ---------------------------------------------------------------------------
# Filenames
# ---------------------------------------------------------------------------


def build_filename(prefix: str, fmt: ExportFormat, generated_at: datetime) -> str:
    """Build a download filename such as ``netpulse_incidents_20261026T143000Z.csv``.

    The prefix may only contain ASCII letters, digits, underscores and hyphens so the
    result is always safe to use in a Content-Disposition header.
    """
    if not _FILENAME_PREFIX_PATTERN.fullmatch(prefix):
        raise ValueError(
            f"Filename prefix {prefix!r} may only contain ASCII letters, digits, '_' and '-'"
        )
    export_format = ExportFormat(fmt)
    stamp = _to_utc(generated_at).strftime(_FILENAME_TIMESTAMP_FORMAT)
    return f"{prefix}_{stamp}.{export_format.value}"
