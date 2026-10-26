"""Tests for the pure JSON/CSV report exporters."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.enums import (
    AlertSeverity,
    AnomalyType,
    ExportFormat,
    NodeRole,
    NodeStatus,
    PortState,
    RiskLevel,
)
from app.schemas import (
    AnomalyAlertRead,
    MetricSampleRead,
    NodeRead,
    PortAuditRead,
    PortFindingRead,
)
from app.services.report_exporter import (
    ALERT_CSV_COLUMNS,
    AUDIT_CSV_COLUMNS,
    METRIC_CSV_COLUMNS,
    alerts_to_csv,
    alerts_to_json,
    audit_to_csv,
    audit_to_json,
    build_filename,
    metrics_to_csv,
    metrics_to_json,
)

T0 = datetime(2026, 10, 26, 14, 0, 0, tzinfo=UTC)
GENERATED_AT = datetime(2026, 10, 26, 14, 30, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def make_node(node_id: int = 1, hostname: str = "web-01") -> NodeRead:
    return NodeRead(
        id=node_id,
        hostname=hostname,
        display_name=f"{hostname} display",
        role=NodeRole.WEB_SERVER,
        ip_address="10.0.0.5",
        os_name="Ubuntu 24.04",
        location="dc-1",
        is_simulated=True,
        cpu_cores=8,
        memory_total_mb=16384.0,
        disk_total_gb=500.0,
        link_capacity_mbps=1000.0,
        status=NodeStatus.WARNING,
        created_at=T0,
        last_seen_at=None,
    )


def make_alert(
    alert_id: int,
    *,
    node_id: int,
    hostname: str | None,
    anomaly_type: AnomalyType,
    severity: AlertSeverity,
    message: str = "sustained anomaly",
    acknowledged: bool = False,
) -> AnomalyAlertRead:
    return AnomalyAlertRead(
        id=alert_id,
        node_id=node_id,
        node_hostname=hostname,
        detected_at=T0 + timedelta(minutes=alert_id),
        anomaly_type=anomaly_type,
        severity=severity,
        metric_name="cpu_percent",
        observed_value=95.5,
        baseline_mean=40.0,
        baseline_std=5.0,
        z_score=11.1,
        threshold=3.0,
        message=message,
        acknowledged=acknowledged,
        acknowledged_at=T0 + timedelta(minutes=alert_id, seconds=30) if acknowledged else None,
    )


def make_alerts() -> list[AnomalyAlertRead]:
    return [
        make_alert(
            1,
            node_id=1,
            hostname="web-01",
            anomaly_type=AnomalyType.CPU_SPIKE,
            severity=AlertSeverity.WARNING,
        ),
        make_alert(
            2,
            node_id=2,
            hostname="db-01",
            anomaly_type=AnomalyType.MEMORY_LEAK,
            severity=AlertSeverity.CRITICAL,
            acknowledged=True,
        ),
        make_alert(
            3,
            node_id=1,
            hostname="web-01",
            anomaly_type=AnomalyType.CPU_SPIKE,
            severity=AlertSeverity.CRITICAL,
            message='Line one, "quoted"\nLine two',
        ),
        make_alert(
            4,
            node_id=3,
            hostname=None,
            anomaly_type=AnomalyType.BANDWIDTH_SATURATION,
            severity=AlertSeverity.WARNING,
        ),
    ]


def make_sample(
    sample_id: int,
    *,
    minute: int,
    cpu: float,
    memory: float,
    disk: float,
    latency: float | None,
    upload: float,
    download: float,
) -> MetricSampleRead:
    return MetricSampleRead(
        id=sample_id,
        node_id=1,
        timestamp=T0 + timedelta(minutes=minute),
        cpu_percent=cpu,
        memory_percent=memory,
        memory_used_mb=8000.0,
        disk_percent=disk,
        latency_ms=latency,
        net_upload_kbps=upload,
        net_download_kbps=download,
        process_count=120,
        temperature_c=None,
    )


def make_samples() -> list[MetricSampleRead]:
    return [
        make_sample(
            1,
            minute=1,
            cpu=10.0,
            memory=50.0,
            disk=60.0,
            latency=20.0,
            upload=100.0,
            download=200.0,
        ),
        make_sample(
            2,
            minute=2,
            cpu=30.0,
            memory=55.0,
            disk=60.0,
            latency=None,
            upload=300.0,
            download=100.0,
        ),
        make_sample(
            3,
            minute=3,
            cpu=20.0,
            memory=60.0,
            disk=61.0,
            latency=40.0,
            upload=200.0,
            download=300.0,
        ),
    ]


def make_audit(findings: list[PortFindingRead] | None = None) -> PortAuditRead:
    if findings is None:
        findings = [
            PortFindingRead(
                id=1,
                audit_id=7,
                port=22,
                protocol="tcp",
                service="ssh",
                state=PortState.OPEN,
                banner="OpenSSH_9.6",
                response_ms=2.1,
                risk_level=RiskLevel.MEDIUM,
                risk_reason="Remote shell exposed",
                recommendation="Restrict access by source IP",
            ),
            PortFindingRead(
                id=2,
                audit_id=7,
                port=3306,
                protocol="tcp",
                service="mysql",
                state=PortState.OPEN,
                banner=None,
                response_ms=None,
                risk_level=RiskLevel.HIGH,
                risk_reason="Database reachable from the network",
                recommendation="Bind the database to localhost",
            ),
            PortFindingRead(
                id=3,
                audit_id=7,
                port=8080,
                protocol="tcp",
                service="http-alt",
                state=PortState.FILTERED,
                banner=None,
                response_ms=None,
                risk_level=RiskLevel.INFO,
                risk_reason="Port did not answer",
                recommendation="No action required",
            ),
        ]
    return PortAuditRead(
        id=7,
        node_id=1,
        target_host="scan.example.lan",
        resolved_ip="10.0.0.20",
        started_at=T0,
        finished_at=T0 + timedelta(seconds=2),
        duration_ms=1234.5,
        host_reachable=True,
        host_latency_ms=3.2,
        total_ports_scanned=3,
        open_ports_count=2,
        risk_score=62.5,
        overall_risk=RiskLevel.HIGH,
        findings=findings,
    )


def parse_csv(text: str) -> tuple[list[str], list[dict[str, str]]]:
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    return reader.fieldnames or [], rows


# ---------------------------------------------------------------------------
# Anomaly alerts
# ---------------------------------------------------------------------------


def test_alerts_to_json_report_metadata_and_items() -> None:
    alerts = make_alerts()
    parsed = json.loads(
        alerts_to_json(alerts, generated_at=GENERATED_AT, filters={"acknowledged": None})
    )

    assert parsed["report"]["title"] == "NetPulse SysGuard - Anomaly Incident Report"
    assert parsed["report"]["generator"] == "NetPulse SysGuard"
    assert parsed["report"]["generated_at"] == "2026-10-26T14:30:00Z"
    assert parsed["report"]["filters"] == {"acknowledged": None}
    assert len(parsed["items"]) == len(alerts)
    assert parsed["items"][0]["id"] == 1
    assert parsed["items"][0]["anomaly_type"] == "cpu_spike"
    assert parsed["items"][0]["detected_at"] == "2026-10-26T14:01:00Z"


def test_alerts_to_json_summary_counts() -> None:
    parsed = json.loads(
        alerts_to_json(make_alerts(), generated_at=GENERATED_AT, filters={})
    )
    summary = parsed["summary"]

    assert summary["total"] == 4
    assert summary["by_severity"] == {"info": 0, "warning": 2, "critical": 2}
    assert summary["by_type"] == {
        "cpu_spike": 2,
        "memory_leak": 1,
        "bandwidth_saturation": 1,
        "critical_latency": 0,
        "disk_pressure": 0,
    }
    assert summary["by_node"] == {"web-01": 2, "db-01": 1, "node_3": 1}


def test_alerts_to_json_serialises_datetime_and_enum_filters() -> None:
    filters = {
        "since": datetime(2026, 10, 25, tzinfo=UTC),
        "severity": AlertSeverity.CRITICAL,
        "node_id": 2,
    }
    parsed = json.loads(alerts_to_json(make_alerts(), generated_at=GENERATED_AT, filters=filters))

    assert parsed["report"]["filters"] == {
        "since": "2026-10-25T00:00:00Z",
        "severity": "critical",
        "node_id": 2,
    }


def test_alerts_to_json_empty_input() -> None:
    parsed = json.loads(alerts_to_json([], generated_at=GENERATED_AT, filters={}))

    assert parsed["items"] == []
    assert parsed["summary"]["total"] == 0
    assert parsed["summary"]["by_node"] == {}
    assert all(count == 0 for count in parsed["summary"]["by_severity"].values())
    assert all(count == 0 for count in parsed["summary"]["by_type"].values())


def test_alerts_to_json_keeps_unicode_unescaped() -> None:
    alert = make_alert(
        1,
        node_id=1,
        hostname="web-01",
        anomaly_type=AnomalyType.CPU_SPIKE,
        severity=AlertSeverity.INFO,
        message="Sobrecarga de CPU ✓",
    )
    text = alerts_to_json([alert], generated_at=GENERATED_AT, filters={})

    assert "Sobrecarga de CPU ✓" in text


def test_alerts_to_csv_header_and_row_count() -> None:
    alerts = make_alerts()
    fieldnames, rows = parse_csv(alerts_to_csv(alerts))

    assert fieldnames == [
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
    ]
    assert tuple(fieldnames) == ALERT_CSV_COLUMNS
    assert len(rows) == len(alerts)


def test_alerts_to_csv_values_and_none_handling() -> None:
    _, rows = parse_csv(alerts_to_csv(make_alerts()))

    first = rows[0]
    assert first["id"] == "1"
    assert first["detected_at"] == "2026-10-26T14:01:00Z"
    assert first["anomaly_type"] == "cpu_spike"
    assert first["severity"] == "warning"
    assert first["acknowledged"] == "false"
    assert first["acknowledged_at"] == ""

    acknowledged = rows[1]
    assert acknowledged["acknowledged"] == "true"
    assert acknowledged["acknowledged_at"] == "2026-10-26T14:02:30Z"

    unattributed = rows[3]
    assert unattributed["node_hostname"] == ""


def test_alerts_to_csv_quotes_commas_and_newlines() -> None:
    text = alerts_to_csv(make_alerts())
    _, rows = parse_csv(text)

    assert rows[2]["message"] == 'Line one, "quoted"\nLine two'
    assert "\r" not in text
    assert text.endswith("\n")


def test_alerts_to_csv_empty_input_writes_header_only() -> None:
    text = alerts_to_csv([])
    fieldnames, rows = parse_csv(text)

    assert fieldnames == list(ALERT_CSV_COLUMNS)
    assert rows == []


# ---------------------------------------------------------------------------
# Node metrics
# ---------------------------------------------------------------------------


def test_metrics_to_json_metadata_and_samples() -> None:
    node = make_node()
    parsed = json.loads(
        metrics_to_json(node, make_samples(), generated_at=GENERATED_AT, window_hours=6.0)
    )

    assert parsed["report"]["title"] == "NetPulse SysGuard - Node Metrics Report"
    assert parsed["report"]["generator"] == "NetPulse SysGuard"
    assert parsed["report"]["generated_at"] == "2026-10-26T14:30:00Z"
    assert parsed["report"]["window_hours"] == 6.0
    assert parsed["node"]["hostname"] == "web-01"
    assert parsed["node"]["status"] == "warning"
    assert len(parsed["samples"]) == 3
    assert parsed["samples"][0]["timestamp"] == "2026-10-26T14:01:00Z"


def test_metrics_to_json_summary_statistics() -> None:
    parsed = json.loads(
        metrics_to_json(make_node(), make_samples(), generated_at=GENERATED_AT, window_hours=1.0)
    )
    summary = parsed["summary"]

    assert summary["sample_count"] == 3
    assert summary["cpu_percent"] == {"min": 10.0, "max": 30.0, "avg": 20.0}
    assert summary["memory_percent"] == {"min": 50.0, "max": 60.0, "avg": 55.0}
    assert summary["disk_percent"] == {"min": 60.0, "max": 61.0, "avg": 60.333}
    assert summary["net_upload_kbps"] == {"min": 100.0, "max": 300.0, "avg": 200.0}
    assert summary["net_download_kbps"] == {"min": 100.0, "max": 300.0, "avg": 200.0}


def test_metrics_to_json_latency_ignores_none_values() -> None:
    parsed = json.loads(
        metrics_to_json(make_node(), make_samples(), generated_at=GENERATED_AT, window_hours=1.0)
    )

    assert parsed["summary"]["latency_ms"] == {"min": 20.0, "max": 40.0, "avg": 30.0}


def test_metrics_to_json_latency_all_none_yields_null_stats() -> None:
    samples = [
        make_sample(
            1,
            minute=1,
            cpu=5.0,
            memory=10.0,
            disk=20.0,
            latency=None,
            upload=0.0,
            download=0.0,
        )
    ]
    parsed = json.loads(
        metrics_to_json(make_node(), samples, generated_at=GENERATED_AT, window_hours=1.0)
    )

    assert parsed["summary"]["latency_ms"] == {"min": None, "max": None, "avg": None}


def test_metrics_to_json_empty_samples() -> None:
    parsed = json.loads(
        metrics_to_json(make_node(), [], generated_at=GENERATED_AT, window_hours=1.0)
    )

    assert parsed["samples"] == []
    assert parsed["summary"]["sample_count"] == 0
    assert parsed["summary"]["cpu_percent"] == {"min": None, "max": None, "avg": None}


def test_metrics_to_csv_header_hostname_and_rows() -> None:
    node = make_node(hostname="db-02")
    fieldnames, rows = parse_csv(metrics_to_csv(node, make_samples()))

    assert fieldnames == [
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
    ]
    assert tuple(fieldnames) == METRIC_CSV_COLUMNS
    assert len(rows) == 3
    assert {row["hostname"] for row in rows} == {"db-02"}
    assert {row["node_id"] for row in rows} == {"1"}


def test_metrics_to_csv_none_values_become_empty_cells() -> None:
    _, rows = parse_csv(metrics_to_csv(make_node(), make_samples()))

    assert rows[1]["latency_ms"] == ""
    assert rows[1]["temperature_c"] == ""
    assert rows[0]["latency_ms"] == "20.0"
    assert rows[0]["timestamp"] == "2026-10-26T14:01:00Z"


def test_metrics_to_csv_empty_samples_writes_header_only() -> None:
    fieldnames, rows = parse_csv(metrics_to_csv(make_node(), []))

    assert fieldnames == list(METRIC_CSV_COLUMNS)
    assert rows == []


# ---------------------------------------------------------------------------
# Port audits
# ---------------------------------------------------------------------------


def test_audit_to_json_metadata_and_findings() -> None:
    parsed = json.loads(audit_to_json(make_audit(), generated_at=GENERATED_AT))

    assert parsed["report"]["title"] == "NetPulse SysGuard - Port Audit Report"
    assert parsed["report"]["generator"] == "NetPulse SysGuard"
    assert parsed["report"]["generated_at"] == "2026-10-26T14:30:00Z"
    assert parsed["audit"]["target_host"] == "scan.example.lan"
    assert parsed["audit"]["resolved_ip"] == "10.0.0.20"
    assert parsed["audit"]["overall_risk"] == "high"
    assert "findings" not in parsed["audit"]
    assert len(parsed["findings"]) == 3
    assert parsed["findings"][1]["service"] == "mysql"
    assert parsed["findings"][1]["risk_level"] == "high"


def test_audit_to_json_summary() -> None:
    parsed = json.loads(audit_to_json(make_audit(), generated_at=GENERATED_AT))
    summary = parsed["summary"]

    assert summary["open_ports"] == 2
    assert summary["open_port_numbers"] == [22, 3306]
    assert summary["total_ports_scanned"] == 3
    assert summary["risk_score"] == 62.5
    assert summary["overall_risk"] == "high"
    assert summary["findings_total"] == 3
    assert summary["counts_by_risk_level"] == {
        "info": 1,
        "low": 0,
        "medium": 1,
        "high": 1,
        "critical": 0,
    }


def test_audit_to_json_empty_findings() -> None:
    parsed = json.loads(audit_to_json(make_audit(findings=[]), generated_at=GENERATED_AT))

    assert parsed["findings"] == []
    assert parsed["summary"]["findings_total"] == 0
    assert parsed["summary"]["counts_by_risk_level"] == {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }


def test_audit_to_csv_header_and_one_row_per_finding() -> None:
    audit = make_audit()
    fieldnames, rows = parse_csv(audit_to_csv(audit))

    assert fieldnames == [
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
    ]
    assert tuple(fieldnames) == AUDIT_CSV_COLUMNS
    assert len(rows) == len(audit.findings)


def test_audit_to_csv_repeats_audit_columns_on_each_row() -> None:
    _, rows = parse_csv(audit_to_csv(make_audit()))

    assert {row["target_host"] for row in rows} == {"scan.example.lan"}
    assert {row["resolved_ip"] for row in rows} == {"10.0.0.20"}
    assert {row["started_at"] for row in rows} == {"2026-10-26T14:00:00Z"}
    assert {row["audit_id"] for row in rows} == {"7"}


def test_audit_to_csv_finding_values_and_none_handling() -> None:
    _, rows = parse_csv(audit_to_csv(make_audit()))

    assert rows[0]["port"] == "22"
    assert rows[0]["banner"] == "OpenSSH_9.6"
    assert rows[0]["state"] == "open"
    assert rows[1]["banner"] == ""
    assert rows[1]["response_ms"] == ""
    assert rows[2]["state"] == "filtered"
    assert rows[2]["risk_level"] == "info"


def test_audit_to_csv_empty_findings_writes_header_only() -> None:
    fieldnames, rows = parse_csv(audit_to_csv(make_audit(findings=[])))

    assert fieldnames == list(AUDIT_CSV_COLUMNS)
    assert rows == []


# ---------------------------------------------------------------------------
# Filenames
# ---------------------------------------------------------------------------


def test_build_filename_csv_format() -> None:
    name = build_filename(
        "netpulse_incidents",
        ExportFormat.CSV,
        datetime(2026, 10, 26, 14, 30, 0, tzinfo=UTC),
    )

    assert name == "netpulse_incidents_20261026T143000Z.csv"


def test_build_filename_json_format() -> None:
    name = build_filename(
        "netpulse_audit",
        ExportFormat.JSON,
        datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
    )

    assert name == "netpulse_audit_20260102T030405Z.json"


def test_build_filename_converts_aware_datetime_to_utc() -> None:
    local = datetime(2026, 10, 26, 16, 30, 0, tzinfo=timezone(timedelta(hours=2)))
    name = build_filename("netpulse_metrics", ExportFormat.CSV, local)

    assert name == "netpulse_metrics_20261026T143000Z.csv"


def test_build_filename_treats_naive_datetime_as_utc() -> None:
    name = build_filename("netpulse_metrics", ExportFormat.JSON, datetime(2026, 10, 26, 14, 30, 0))

    assert name == "netpulse_metrics_20261026T143000Z.json"


def test_build_filename_matches_expected_pattern() -> None:
    name = build_filename("netpulse_incidents", ExportFormat.CSV, GENERATED_AT)

    assert re.fullmatch(r"netpulse_incidents_\d{8}T\d{6}Z\.csv", name)


@pytest.mark.parametrize("prefix", ["", "bad prefix", "../escape", "name.with.dots", "naïve"])
def test_build_filename_rejects_unsafe_prefix(prefix: str) -> None:
    with pytest.raises(ValueError):
        build_filename(prefix, ExportFormat.CSV, GENERATED_AT)
