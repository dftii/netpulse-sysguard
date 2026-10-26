"""End-to-end API tests: lifespan startup, live pipeline, WebSocket stream, scans, incidents and exports."""

from __future__ import annotations

import csv
import io
import json
import socket
import threading
import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if test_client.get("/api/telemetry/latest").status_code == 200:
                break
            time.sleep(0.2)
        yield test_client


@pytest.fixture(scope="module")
def listening_port() -> Iterator[int]:
    """A real local TCP service for the port audit tests."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    server.settimeout(0.2)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except (TimeoutError, OSError):
                continue
            try:
                connection.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            finally:
                connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    thread.join(timeout=2)
    server.close()


def test_health(client: TestClient) -> None:
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["telemetry_ticks"] >= 1


def test_nodes_seeded(client: TestClient) -> None:
    nodes = client.get("/api/nodes").json()
    assert len(nodes) == 9
    assert sum(1 for node in nodes if not node["is_simulated"]) == 1
    node_id = nodes[0]["id"]
    assert client.get(f"/api/nodes/{node_id}").json()["id"] == node_id
    assert client.get("/api/nodes/999999").status_code == 404


def test_latest_telemetry_and_metrics(client: TestClient) -> None:
    latest = client.get("/api/telemetry/latest").json()
    assert latest["type"] == "telemetry"
    assert latest["summary"]["total_nodes"] == 9
    node_id = latest["nodes"][0]["node_id"]
    metrics = client.get(f"/api/nodes/{node_id}/metrics", params={"minutes": 5}).json()
    assert len(metrics) >= 1
    assert {"cpu_percent", "memory_percent", "latency_ms", "net_upload_kbps"} <= metrics[0].keys()
    baseline = client.get(f"/api/nodes/{node_id}/baseline").json()
    assert "cpu_percent" in baseline


def test_websocket_stream(client: TestClient) -> None:
    with client.websocket_connect("/ws/telemetry") as websocket:
        first = websocket.receive_json()
        second = websocket.receive_json()
        assert first["type"] == "telemetry"
        assert len(second["nodes"]) == 9
        assert second["tick"] >= first["tick"]
        websocket.send_text("ping")
        for _ in range(5):
            message = websocket.receive_json()
            if message.get("type") == "pong":
                break
        else:
            pytest.fail("No pong received")


def test_port_scan_lifecycle(client: TestClient, listening_port: int) -> None:
    response = client.post(
        "/api/scans",
        json={"target": "127.0.0.1", "ports": [listening_port], "timeout_seconds": 1.0},
    )
    assert response.status_code == 201, response.text
    audit = response.json()
    assert audit["open_ports_count"] == 1
    assert audit["findings"][0]["port"] == listening_port
    assert audit["host_reachable"] is True

    assert client.get(f"/api/scans/{audit['id']}").json()["id"] == audit["id"]
    assert any(item["id"] == audit["id"] for item in client.get("/api/scans").json())

    exported = client.get(f"/api/reports/scans/{audit['id']}", params={"format": "csv"})
    assert exported.status_code == 200
    assert "attachment" in exported.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    assert len(rows) == 1


def test_port_scan_rejects_public_target(client: TestClient) -> None:
    response = client.post("/api/scans", json={"target": "8.8.8.8", "ports": [53]})
    assert response.status_code == 400


def test_incident_injection_detected_and_exported(client: TestClient) -> None:
    nodes = client.get("/api/nodes").json()
    simulated = next(node for node in nodes if node["is_simulated"])
    host = next(node for node in nodes if not node["is_simulated"])

    assert (
        client.post(
            "/api/simulation/incidents",
            json={"hostname": host["hostname"], "anomaly_type": "cpu_spike", "duration_seconds": 10},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/simulation/incidents",
            json={"hostname": "ghost-node", "anomaly_type": "cpu_spike", "duration_seconds": 10},
        ).status_code
        == 404
    )

    response = client.post(
        "/api/simulation/incidents",
        json={"hostname": simulated["hostname"], "anomaly_type": "bandwidth_saturation", "duration_seconds": 30},
    )
    assert response.status_code == 202

    deadline = time.monotonic() + 10
    alerts: list[dict] = []
    while time.monotonic() < deadline:
        page = client.get(
            "/api/alerts", params={"node_id": simulated["id"], "anomaly_type": "bandwidth_saturation"}
        ).json()
        alerts = page["items"]
        if alerts:
            break
        time.sleep(0.5)
    assert alerts, "Injected bandwidth saturation was not detected"
    assert alerts[0]["node_hostname"] == simulated["hostname"]

    acknowledged = client.patch(f"/api/alerts/{alerts[0]['id']}/acknowledge").json()
    assert acknowledged["acknowledged"] is True
    assert acknowledged["acknowledged_at"] is not None

    report = client.get("/api/reports/incidents", params={"format": "json"})
    assert report.status_code == 200
    assert json.loads(report.text)["items"]

    csv_report = client.get("/api/reports/incidents", params={"format": "csv", "severity": "critical"})
    assert csv_report.status_code == 200
    assert csv_report.headers["content-type"].startswith("text/csv")


def test_service_down_keeps_node_offline(client: TestClient) -> None:
    nodes = [node for node in client.get("/api/nodes").json() if node["is_simulated"]]
    target = nodes[-1]

    response = client.post(
        "/api/simulation/incidents",
        json={"hostname": target["hostname"], "anomaly_type": "service_down", "duration_seconds": 20},
    )
    assert response.status_code == 202

    deadline = time.monotonic() + 12
    alerts: list[dict] = []
    while time.monotonic() < deadline:
        page = client.get("/api/alerts", params={"node_id": target["id"], "anomaly_type": "service_down"}).json()
        alerts = page["items"]
        if alerts:
            break
        time.sleep(0.5)
    assert alerts, "Injected service outage was not detected"
    assert alerts[0]["severity"] == "critical"

    # The critical SERVICE_DOWN alert must not escalate the unreachable node to CRITICAL.
    latest = client.get("/api/telemetry/latest").json()
    snapshot = next(node for node in latest["nodes"] if node["node_id"] == target["id"])
    assert snapshot["status"] == "offline"
    assert snapshot["latency_ms"] is None
    assert snapshot["simulated_incident"] == "service_down"
    assert latest["summary"]["offline"] >= 1
    assert client.get(f"/api/nodes/{target['id']}").json()["status"] == "offline"


def test_metrics_report(client: TestClient) -> None:
    node_id = client.get("/api/nodes").json()[0]["id"]
    json_report = client.get(f"/api/reports/metrics/{node_id}", params={"hours": 1})
    assert json_report.status_code == 200
    assert json.loads(json_report.text)["samples"]
    csv_report = client.get(f"/api/reports/metrics/{node_id}", params={"hours": 1, "format": "csv"})
    assert len(list(csv.DictReader(io.StringIO(csv_report.text)))) >= 1


def test_alert_filters_validation(client: TestClient) -> None:
    response = client.get(
        "/api/alerts", params={"since": "2026-01-02T00:00:00Z", "until": "2026-01-01T00:00:00Z"}
    )
    assert response.status_code == 422
    assert client.patch("/api/alerts/999999/acknowledge").status_code == 404
