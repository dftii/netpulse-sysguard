"""Tests for the asynchronous port scanner; everything runs offline against loopback."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest

from app.config import Settings
from app.enums import PortState, RiskLevel
from app.services import network_scanner
from app.services.network_scanner import (
    COMMON_PORTS,
    NetworkScanner,
    PortProfile,
    ScanTargetError,
    calculate_risk_score,
    classify_connect_error,
    highest_risk,
    parse_ping_latency,
    sanitize_banner,
)


def make_scanner(**overrides: object) -> NetworkScanner:
    return NetworkScanner(Settings(**overrides))


@asynccontextmanager
async def banner_server(banner: bytes) -> AsyncIterator[int]:
    """Run a local TCP server that greets every client with ``banner`` and returns its port."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.write(banner)
            await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


def free_closed_port() -> int:
    """Return a TCP port that was just released, so nothing is listening on it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def no_ping(self: NetworkScanner, ip: str, timeout: float) -> float | None:
    return None


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_reports_open_port_with_banner_and_escalated_risk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NetworkScanner, "_icmp_ping", no_ping)
    scanner = make_scanner()
    async with banner_server(b"SSH-2.0-OpenSSH_7.4\r\n") as open_port:
        closed_port = free_closed_port()
        outcome = await scanner.scan("127.0.0.1", [open_port, closed_port], timeout=2.0)

    assert outcome.resolved_ip == "127.0.0.1"
    assert outcome.target_host == "127.0.0.1"
    assert outcome.total_ports_scanned == 2
    assert outcome.open_ports_count == 1
    assert outcome.host_reachable is True
    assert outcome.host_latency_ms is not None and outcome.host_latency_ms >= 0
    assert outcome.finished_at >= outcome.started_at
    assert outcome.duration_ms > 0

    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    assert finding.port == open_port
    assert finding.state is PortState.OPEN
    assert finding.banner == "SSH-2.0-OpenSSH_7.4"
    assert finding.service == "ssh"
    assert finding.risk_level is RiskLevel.HIGH
    assert "OpenSSH 7.4" in finding.risk_reason
    assert finding.response_ms is not None
    assert outcome.overall_risk is RiskLevel.HIGH
    assert outcome.risk_score == 30.0


@pytest.mark.asyncio
async def test_scan_without_banner_grab_keeps_base_risk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NetworkScanner, "_icmp_ping", no_ping)
    scanner = make_scanner()
    async with banner_server(b"SSH-2.0-OpenSSH_7.4\r\n") as open_port:
        outcome = await scanner.scan("127.0.0.1", [open_port], timeout=2.0, grab_banners=False)

    finding = outcome.findings[0]
    assert finding.banner is None
    assert finding.service == "unknown"
    assert finding.risk_level is RiskLevel.LOW
    assert outcome.risk_score == 5.0


@pytest.mark.asyncio
async def test_scan_with_no_open_ports_uses_ping_and_reports_info(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_ping(self: NetworkScanner, ip: str, timeout: float) -> float | None:
        return 4.2

    monkeypatch.setattr(NetworkScanner, "_icmp_ping", fake_ping)
    scanner = make_scanner()
    outcome = await scanner.scan("127.0.0.1", [free_closed_port()], timeout=1.0)

    assert outcome.findings == []
    assert outcome.open_ports_count == 0
    assert outcome.total_ports_scanned == 1
    assert outcome.overall_risk is RiskLevel.INFO
    assert outcome.risk_score == 0.0
    assert outcome.host_reachable is True
    assert outcome.host_latency_ms == 4.2


@pytest.mark.asyncio
async def test_scan_deduplicates_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NetworkScanner, "_icmp_ping", no_ping)
    scanner = make_scanner()
    async with banner_server(b"hello\r\n") as open_port:
        outcome = await scanner.scan("127.0.0.1", [open_port, open_port], timeout=2.0)

    assert outcome.total_ports_scanned == 1
    assert outcome.findings[0].banner == "hello"


@pytest.mark.asyncio
async def test_default_catalogue_is_scanned_when_ports_omitted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(NetworkScanner, "_icmp_ping", no_ping)
    scanner = make_scanner()
    outcome = await scanner.scan("127.0.0.1", None, timeout=0.3, concurrency=500)

    assert outcome.total_ports_scanned == len(COMMON_PORTS)
    assert all(finding.port in COMMON_PORTS for finding in outcome.findings)


# ---------------------------------------------------------------------------
# Target and port validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_public_target_rejected_by_default_and_allowed_when_enabled() -> None:
    with pytest.raises(ScanTargetError, match="public"):
        await make_scanner().resolve_target("8.8.8.8")

    permissive = make_scanner(scan_allow_public_targets=True)
    assert await permissive.resolve_target("8.8.8.8") == "8.8.8.8"


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["", "   ", "a b", "10.0.0.0/24", "0.0.0.0", "::", "224.0.0.1", "255.255.255.255", "http://x"])
async def test_invalid_targets_are_rejected(target: str) -> None:
    with pytest.raises(ScanTargetError):
        await make_scanner().resolve_target(target)


@pytest.mark.asyncio
async def test_unspecified_and_multicast_rejected_even_when_public_allowed() -> None:
    scanner = make_scanner(scan_allow_public_targets=True)
    for target in ("0.0.0.0", "224.0.0.1", "ff02::1"):
        with pytest.raises(ScanTargetError):
            await scanner.resolve_target(target)


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["127.0.0.1", "192.168.1.10", "10.1.2.3", "172.16.0.5", "169.254.1.1", "::1"])
async def test_private_loopback_and_link_local_targets_are_allowed(target: str) -> None:
    assert await make_scanner().resolve_target(target) == target


@pytest.mark.asyncio
async def test_localhost_hostname_resolves_to_loopback() -> None:
    assert await make_scanner().resolve_target("localhost") == "127.0.0.1"


@pytest.mark.asyncio
async def test_unresolvable_hostname_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", failing_getaddrinfo)
    with pytest.raises(ScanTargetError, match="Cannot resolve"):
        await make_scanner().resolve_target("no-such-host.internal")


@pytest.mark.asyncio
async def test_hostname_resolving_to_public_address_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def public_getaddrinfo(host: str, port: object, family: int = 0, type: int = 0, *args: object, **kwargs: object):
        if family == socket.AF_INET:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
        raise socket.gaierror(socket.EAI_NONAME, "no AAAA")

    monkeypatch.setattr(socket, "getaddrinfo", public_getaddrinfo)
    with pytest.raises(ScanTargetError, match="disallowed"):
        await make_scanner().resolve_target("dns.example.test")
    assert await make_scanner(scan_allow_public_targets=True).resolve_target("dns.example.test") == "8.8.8.8"


@pytest.mark.asyncio
async def test_too_many_ports_rejected() -> None:
    scanner = make_scanner(scan_max_ports=3)
    with pytest.raises(ScanTargetError, match="Too many ports"):
        await scanner.scan("127.0.0.1", [1, 2, 3, 4])


@pytest.mark.asyncio
@pytest.mark.parametrize("ports", [[], [0], [70000]])
async def test_invalid_port_lists_rejected(ports: list[int]) -> None:
    with pytest.raises(ScanTargetError):
        await make_scanner().scan("127.0.0.1", ports)


@pytest.mark.asyncio
async def test_scan_rejects_public_target_before_connecting() -> None:
    with pytest.raises(ScanTargetError):
        await make_scanner().scan("8.8.8.8", [80])


# ---------------------------------------------------------------------------
# Classification and scoring
# ---------------------------------------------------------------------------


def test_classify_known_and_unknown_ports() -> None:
    scanner = make_scanner()
    rdp = scanner.classify_port(3389)
    assert isinstance(rdp, PortProfile)
    assert rdp.service == "rdp"
    assert rdp.risk_level is RiskLevel.CRITICAL

    high_unknown = scanner.classify_port(49152)
    assert high_unknown.service == "unknown"
    assert high_unknown.risk_level is RiskLevel.LOW

    privileged_unknown = scanner.classify_port(999)
    assert privileged_unknown.service == "unknown"
    assert privileged_unknown.risk_level is RiskLevel.MEDIUM


def test_catalogue_covers_required_ports_with_actionable_text() -> None:
    required = {
        20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995,
        1433, 1521, 1883, 2049, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5672, 5900, 5985, 5986, 6379,
        8000, 8080, 8443, 9090, 9200, 11211, 27017,
    }  # fmt: skip
    assert required <= set(COMMON_PORTS)
    for profile in COMMON_PORTS.values():
        assert profile.service and profile.risk_reason and profile.recommendation
    assert COMMON_PORTS[23].risk_level is RiskLevel.CRITICAL
    assert COMMON_PORTS[445].risk_level is RiskLevel.CRITICAL
    assert COMMON_PORTS[443].risk_level is RiskLevel.LOW


def test_banner_based_escalation_rules() -> None:
    scanner = make_scanner()
    assert scanner.classify_port(22, "SSH-2.0-OpenSSH_7.4").risk_level is RiskLevel.HIGH
    assert scanner.classify_port(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu").risk_level is RiskLevel.MEDIUM
    assert scanner.classify_port(21, "220 (vsFTPd 2.3.4)").risk_level is RiskLevel.CRITICAL
    assert scanner.classify_port(21, "220 (vsFTPd 3.0.3)").risk_level is RiskLevel.HIGH
    assert scanner.classify_port(80, "HTTP/1.1 200 OK | Server: Apache/2.2.15").risk_level is RiskLevel.HIGH
    # Escalation never lowers an already critical profile.
    assert scanner.classify_port(23, "SSH-2.0-OpenSSH_5.3").risk_level is RiskLevel.CRITICAL


def test_risk_score_math() -> None:
    assert calculate_risk_score([]) == 0.0
    assert calculate_risk_score([RiskLevel.INFO]) == 0.0
    assert calculate_risk_score([RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]) == 50.0
    assert calculate_risk_score([RiskLevel.CRITICAL, RiskLevel.CRITICAL, RiskLevel.HIGH]) == 100.0
    assert highest_risk([]) is RiskLevel.INFO
    assert highest_risk([RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MEDIUM]) is RiskLevel.CRITICAL


def test_connect_error_classification() -> None:
    assert classify_connect_error(ConnectionRefusedError()) is PortState.CLOSED
    assert classify_connect_error(OSError(10061, "WSAECONNREFUSED")) is PortState.CLOSED
    assert classify_connect_error(OSError(socket.errno.ECONNREFUSED, "refused")) is PortState.CLOSED
    assert classify_connect_error(OSError(65, "No route to host")) is PortState.FILTERED
    assert classify_connect_error(TimeoutError()) is PortState.FILTERED


# ---------------------------------------------------------------------------
# Banner and ping parsing
# ---------------------------------------------------------------------------


def test_sanitize_banner() -> None:
    assert sanitize_banner(b"SSH-2.0-OpenSSH_7.4\r\n") == "SSH-2.0-OpenSSH_7.4"
    assert sanitize_banner(b"HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n") == "HTTP/1.0 200 OK | Server: nginx"
    assert sanitize_banner(b"a\x00b\x07c") == "a b c"
    assert sanitize_banner(b"") is None
    assert sanitize_banner(b"\r\n\x00") is None
    assert sanitize_banner(b"\xff\xfe\xfd\xfc") is None
    assert len(sanitize_banner(b"x" * 500) or "") == 200


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("Reply from 1.1.1.1: bytes=32 time=12ms TTL=57", 12.0),
        ("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64", 0.5),
        ("Respuesta desde 192.168.1.1: bytes=32 tiempo=3ms TTL=64", 3.0),
        ("Respuesta desde 192.168.1.1: bytes=32 tiempo<1m TTL=64", 0.5),
        ("64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms", 0.045),
        ("64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=1,5 ms", 1.5),
        ("Reply from 192.168.1.5: Destination host unreachable.", None),
        ("", None),
    ],
)
def test_parse_ping_latency(output: str, expected: float | None) -> None:
    assert parse_ping_latency(output) == expected


def test_module_exports_logger() -> None:
    assert network_scanner.logger.name == "app.services.network_scanner"
