"""NetPulse SysGuard API: real-time telemetry WebSocket, port audits, incident history and report exports."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import crud
from app.config import Settings, get_settings
from app.database import SessionLocal, dispose_db, get_session, init_db
from app.enums import AlertSeverity, AnomalyType, ExportFormat, NodeStatus
from app.schemas import (
    AlertPage,
    AnomalyAlertRead,
    ClusterSummary,
    HealthResponse,
    IncidentInjectionRequest,
    IncidentInjectionResponse,
    MetricSampleRead,
    NodeRead,
    NodeTelemetry,
    PortAuditRead,
    PortAuditSummary,
    PortScanRequest,
    TelemetryBroadcast,
)
from app.services import report_exporter
from app.services.anomaly_detector import AnomalyDetector
from app.services.network_scanner import NetworkScanner, ScanTargetError
from app.services.telemetry_collector import TelemetryCollector
from app.ws_manager import ConnectionManager

logger = logging.getLogger("netpulse")

MAX_CONCURRENT_SCANS = 2
MAX_METRIC_POINTS = 20_000


@dataclass
class Runtime:
    """Long-lived services and pipeline state shared by every request."""

    settings: Settings
    collector: TelemetryCollector
    detector: AnomalyDetector
    scanner: NetworkScanner
    ws_manager: ConnectionManager
    started_monotonic: float = field(default_factory=time.monotonic)
    tick: int = 0
    latest_broadcast: TelemetryBroadcast | None = None
    scan_semaphore: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(MAX_CONCURRENT_SCANS))
    background_tasks: list[asyncio.Task[None]] = field(default_factory=list)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Telemetry pipeline
# ---------------------------------------------------------------------------


def build_summary(samples: list[NodeTelemetry], unacknowledged_alerts: int) -> ClusterSummary:
    total = len(samples)
    by_status = {state: sum(1 for sample in samples if sample.status == state) for state in NodeStatus}
    return ClusterSummary(
        total_nodes=total,
        online=by_status[NodeStatus.ONLINE],
        warning=by_status[NodeStatus.WARNING],
        critical=by_status[NodeStatus.CRITICAL],
        offline=by_status[NodeStatus.OFFLINE],
        avg_cpu_percent=round(sum(s.cpu_percent for s in samples) / total, 2) if total else 0.0,
        avg_memory_percent=round(sum(s.memory_percent for s in samples) / total, 2) if total else 0.0,
        total_upload_kbps=round(sum(s.net_upload_kbps for s in samples), 2),
        total_download_kbps=round(sum(s.net_download_kbps for s in samples), 2),
        unacknowledged_alerts=unacknowledged_alerts,
    )


async def run_tick(runtime: Runtime) -> TelemetryBroadcast:
    """Collect -> detect & persist incidents -> persist metrics -> broadcast."""
    samples = await runtime.collector.collect()
    runtime.tick += 1
    hostnames = {sample.node_id: sample.hostname for sample in samples}

    async with SessionLocal() as session:
        persisted_alerts = await runtime.detector.analyze_and_persist(session, samples)

        critical_nodes = {
            alert.node_id for alert in persisted_alerts if alert.severity == AlertSeverity.CRITICAL
        }
        warning_nodes = {alert.node_id for alert in persisted_alerts if alert.severity == AlertSeverity.WARNING}
        escalated: list[NodeTelemetry] = []
        for sample in samples:
            if sample.node_id in critical_nodes and sample.status != NodeStatus.CRITICAL:
                sample = sample.model_copy(update={"status": NodeStatus.CRITICAL})
            elif sample.node_id in warning_nodes and sample.status == NodeStatus.ONLINE:
                sample = sample.model_copy(update={"status": NodeStatus.WARNING})
            escalated.append(sample)

        persist_metrics = runtime.tick % runtime.settings.metrics_persist_every_n_ticks == 0
        await crud.record_tick(session, escalated, persist_metrics=persist_metrics)
        unacknowledged = await crud.count_unacknowledged_alerts(session)

    new_alerts = [crud.alert_to_read(alert, hostnames.get(alert.node_id)) for alert in persisted_alerts]
    broadcast = TelemetryBroadcast(
        timestamp=escalated[0].timestamp if escalated else datetime.now(UTC),
        tick=runtime.tick,
        summary=build_summary(escalated, unacknowledged),
        nodes=escalated,
        new_alerts=new_alerts,
    )
    runtime.latest_broadcast = broadcast
    await runtime.ws_manager.broadcast(broadcast.model_dump_json())
    return broadcast


async def telemetry_loop(runtime: Runtime) -> None:
    """Fixed-rate scheduler: keeps a steady cadence and never lets one failed tick kill the stream."""
    loop = asyncio.get_running_loop()
    interval = runtime.settings.telemetry_interval_seconds
    next_run = loop.time()
    while True:
        try:
            await run_tick(runtime)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Telemetry tick %d failed", runtime.tick)
        next_run += interval
        delay = next_run - loop.time()
        if delay < 0:
            logger.debug("Telemetry tick overran its %.2fs budget by %.3fs", interval, -delay)
            next_run = loop.time()
            delay = 0.0
        await asyncio.sleep(delay)


async def retention_loop(runtime: Runtime) -> None:
    """Periodically purge metric samples older than the configured retention window."""
    while True:
        try:
            cutoff = datetime.now(UTC) - timedelta(days=runtime.settings.metrics_retention_days)
            async with SessionLocal() as session:
                removed = await crud.purge_metrics_older_than(session, cutoff)
            if removed:
                logger.info("Retention: purged %d metric samples older than %s", removed, cutoff.isoformat())
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Metric retention job failed")
        await asyncio.sleep(runtime.settings.retention_check_interval_seconds)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info("Starting %s v%s (%s)", settings.app_name, settings.app_version, settings.environment)

    await init_db()
    collector = TelemetryCollector(settings)
    specs = collector.node_specs()
    async with SessionLocal() as session:
        node_ids = await crud.upsert_nodes(session, specs)
        await crud.mark_nodes_offline(session, [spec.hostname for spec in specs])
    collector.bind_node_ids(node_ids)
    logger.info("Monitoring %d nodes (%d simulated)", len(specs), len(collector.simulated_hostnames()))

    runtime = Runtime(
        settings=settings,
        collector=collector,
        detector=AnomalyDetector(settings),
        scanner=NetworkScanner(settings),
        ws_manager=ConnectionManager(settings.ws_max_clients),
    )
    runtime.background_tasks = [
        asyncio.create_task(telemetry_loop(runtime), name="telemetry-loop"),
        asyncio.create_task(retention_loop(runtime), name="retention-loop"),
    ]
    app.state.runtime = runtime
    try:
        yield
    finally:
        for task in runtime.background_tasks:
            task.cancel()
        await asyncio.gather(*runtime.background_tasks, return_exceptions=True)
        await runtime.collector.aclose()
        await runtime.ws_manager.close_all()
        await dispose_db()
        logger.info("%s stopped cleanly", settings.app_name)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

_settings = get_settings()

app = FastAPI(
    title=_settings.app_name,
    version=_settings.app_version,
    description=(
        "IT infrastructure monitoring, local network auditing and real-time anomaly detection. "
        "Streams live telemetry over WebSocket at /ws/telemetry."
    ),
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


def get_runtime(request: Request) -> Runtime:
    return request.app.state.runtime


RuntimeDep = Annotated[Runtime, Depends(get_runtime)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]


def attachment(content: str, fmt: ExportFormat, prefix: str) -> Response:
    generated_at = datetime.now(UTC)
    media_type = "application/json" if fmt == ExportFormat.JSON else "text/csv; charset=utf-8"
    safe_prefix = re.sub(r"[^A-Za-z0-9_-]", "_", prefix)
    filename = report_exporter.build_filename(safe_prefix, fmt, generated_at)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --- Health ---------------------------------------------------------------


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
async def health(runtime: RuntimeDep, session: SessionDep) -> HealthResponse:
    database_state = "ok"
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        logger.exception("Health check: database unreachable")
        database_state = "error"
    pipeline_alive = all(not task.done() for task in runtime.background_tasks)
    return HealthResponse(
        status="ok" if database_state == "ok" and pipeline_alive else "degraded",
        app_name=runtime.settings.app_name,
        version=runtime.settings.app_version,
        environment=runtime.settings.environment,
        uptime_seconds=round(time.monotonic() - runtime.started_monotonic, 1),
        telemetry_ticks=runtime.tick,
        websocket_clients=runtime.ws_manager.client_count,
        database=database_state,
    )


# --- Nodes & live telemetry -----------------------------------------------


@app.get("/api/nodes", response_model=list[NodeRead], tags=["nodes"])
async def list_nodes(session: SessionDep) -> list[NodeRead]:
    return [NodeRead.model_validate(node) for node in await crud.list_nodes(session)]


@app.get("/api/nodes/{node_id}", response_model=NodeRead, tags=["nodes"])
async def get_node(node_id: int, session: SessionDep) -> NodeRead:
    node = await crud.get_node(session, node_id)
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Node {node_id} not found")
    return NodeRead.model_validate(node)


@app.get("/api/nodes/{node_id}/metrics", response_model=list[MetricSampleRead], tags=["nodes"])
async def get_node_metrics(
    node_id: int,
    session: SessionDep,
    minutes: Annotated[int, Query(ge=1, le=60 * 24 * 30)] = 60,
    limit: Annotated[int, Query(ge=1, le=MAX_METRIC_POINTS)] = 2000,
) -> list[MetricSampleRead]:
    if await crud.get_node(session, node_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Node {node_id} not found")
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    samples = await crud.list_metrics(session, node_id, since=since, limit=limit)
    return [MetricSampleRead.model_validate(sample) for sample in samples]


@app.get("/api/nodes/{node_id}/baseline", tags=["nodes"])
async def get_node_baseline(
    node_id: int, runtime: RuntimeDep, session: SessionDep
) -> dict[str, dict[str, float | int | None]]:
    if await crud.get_node(session, node_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Node {node_id} not found")
    return runtime.detector.baseline_snapshot(node_id)


@app.get("/api/telemetry/latest", response_model=TelemetryBroadcast, tags=["telemetry"])
async def latest_telemetry(runtime: RuntimeDep) -> TelemetryBroadcast:
    if runtime.latest_broadcast is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Telemetry pipeline has not produced data yet")
    return runtime.latest_broadcast


@app.websocket("/ws/telemetry")
async def telemetry_stream(websocket: WebSocket) -> None:
    """Pushes a TelemetryBroadcast frame every tick. Clients may send 'ping' and receive 'pong'."""
    runtime: Runtime = websocket.app.state.runtime
    if not await runtime.ws_manager.connect(websocket):
        return
    try:
        if runtime.latest_broadcast is not None:
            await runtime.ws_manager.send_to(websocket, runtime.latest_broadcast.model_dump_json())
        while True:
            message = await websocket.receive_text()
            if message.strip().lower() == "ping":
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        pass
    finally:
        await runtime.ws_manager.disconnect(websocket)


# --- Simulation control ----------------------------------------------------


@app.post(
    "/api/simulation/incidents",
    response_model=IncidentInjectionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["simulation"],
)
async def inject_incident(payload: IncidentInjectionRequest, runtime: RuntimeDep) -> IncidentInjectionResponse:
    try:
        runtime.collector.inject_incident(payload.hostname, payload.anomaly_type, payload.duration_seconds)
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown simulated node '{payload.hostname}'") from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return IncidentInjectionResponse(
        hostname=payload.hostname,
        anomaly_type=payload.anomaly_type,
        duration_seconds=payload.duration_seconds,
        accepted=True,
    )


# --- Port audits ------------------------------------------------------------


@app.post("/api/scans", response_model=PortAuditRead, status_code=status.HTTP_201_CREATED, tags=["scans"])
async def launch_port_scan(payload: PortScanRequest, runtime: RuntimeDep, session: SessionDep) -> PortAuditRead:
    if payload.node_id is not None and await crud.get_node(session, payload.node_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Node {payload.node_id} not found")
    if runtime.scan_semaphore.locked():
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"{MAX_CONCURRENT_SCANS} scans already running; retry when one finishes",
        )
    async with runtime.scan_semaphore:
        try:
            outcome = await runtime.scanner.scan(
                payload.target,
                payload.resolved_ports(),
                timeout=payload.timeout_seconds,
                concurrency=payload.concurrency,
                grab_banners=payload.grab_banners,
            )
        except ScanTargetError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    audit = await crud.save_port_audit(session, outcome, payload.node_id)
    logger.info(
        "Port audit #%d on %s: %d open / %d scanned, risk %s (%.1f)",
        audit.id,
        audit.target_host,
        audit.open_ports_count,
        audit.total_ports_scanned,
        audit.overall_risk,
        audit.risk_score,
    )
    return PortAuditRead.model_validate(audit)


@app.get("/api/scans", response_model=list[PortAuditSummary], tags=["scans"])
async def list_port_scans(
    session: SessionDep,
    target: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[PortAuditSummary]:
    audits = await crud.list_port_audits(session, target=target, limit=limit, offset=offset)
    return [PortAuditSummary.model_validate(audit) for audit in audits]


@app.get("/api/scans/{audit_id}", response_model=PortAuditRead, tags=["scans"])
async def get_port_scan(audit_id: int, session: SessionDep) -> PortAuditRead:
    audit = await crud.get_port_audit(session, audit_id)
    if audit is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Port audit {audit_id} not found")
    return PortAuditRead.model_validate(audit)


# --- Incidents ----------------------------------------------------------------


def alert_filters(
    node_id: int | None = None,
    severity: AlertSeverity | None = None,
    anomaly_type: AnomalyType | None = None,
    acknowledged: bool | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> crud.AlertFilters:
    if since is not None and until is not None and crud.to_utc(since) > crud.to_utc(until):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "'since' must be earlier than 'until'")
    return crud.AlertFilters(
        node_id=node_id,
        severity=severity,
        anomaly_type=anomaly_type,
        acknowledged=acknowledged,
        since=since,
        until=until,
    )


AlertFiltersDep = Annotated[crud.AlertFilters, Depends(alert_filters)]


@app.get("/api/alerts", response_model=AlertPage, tags=["incidents"])
async def list_alerts(
    session: SessionDep,
    filters: AlertFiltersDep,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertPage:
    total, items = await crud.query_alerts(session, filters, limit=limit, offset=offset)
    return AlertPage(total=total, limit=limit, offset=offset, items=items)


@app.patch("/api/alerts/{alert_id}/acknowledge", response_model=AnomalyAlertRead, tags=["incidents"])
async def acknowledge_alert(alert_id: int, session: SessionDep) -> AnomalyAlertRead:
    alert = await crud.acknowledge_alert(session, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Alert {alert_id} not found")
    return alert


# --- Reports ------------------------------------------------------------------


@app.get("/api/reports/incidents", tags=["reports"])
async def export_incidents(
    session: SessionDep,
    filters: AlertFiltersDep,
    format: ExportFormat = ExportFormat.JSON,
) -> Response:
    _, alerts = await crud.query_alerts(session, filters, limit=None)
    if format == ExportFormat.CSV:
        content = report_exporter.alerts_to_csv(alerts)
    else:
        content = report_exporter.alerts_to_json(
            alerts, generated_at=datetime.now(UTC), filters=filters.as_dict()
        )
    return attachment(content, format, "netpulse_incidents")


@app.get("/api/reports/metrics/{node_id}", tags=["reports"])
async def export_node_metrics(
    node_id: int,
    session: SessionDep,
    hours: Annotated[float, Query(gt=0, le=24 * 30)] = 24,
    format: ExportFormat = ExportFormat.JSON,
) -> Response:
    node = await crud.get_node(session, node_id)
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Node {node_id} not found")
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = await crud.list_metrics(session, node_id, since=since, limit=1_000_000)
    node_read = NodeRead.model_validate(node)
    samples = [MetricSampleRead.model_validate(row) for row in rows]
    if format == ExportFormat.CSV:
        content = report_exporter.metrics_to_csv(node_read, samples)
    else:
        content = report_exporter.metrics_to_json(
            node_read, samples, generated_at=datetime.now(UTC), window_hours=hours
        )
    return attachment(content, format, f"netpulse_metrics_{node.hostname}")


@app.get("/api/reports/scans/{audit_id}", tags=["reports"])
async def export_port_scan(
    audit_id: int,
    session: SessionDep,
    format: ExportFormat = ExportFormat.JSON,
) -> Response:
    audit = await crud.get_port_audit(session, audit_id)
    if audit is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Port audit {audit_id} not found")
    audit_read = PortAuditRead.model_validate(audit)
    if format == ExportFormat.CSV:
        content = report_exporter.audit_to_csv(audit_read)
    else:
        content = report_exporter.audit_to_json(audit_read, generated_at=datetime.now(UTC))
    return attachment(content, format, f"netpulse_port_audit_{audit_id}")
