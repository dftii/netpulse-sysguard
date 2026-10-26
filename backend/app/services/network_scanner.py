"""Asynchronous TCP port scanner and local-network exposure auditor.

The scanner performs a plain TCP connect scan (no raw sockets, no elevated privileges) using
``asyncio.open_connection`` bounded by a semaphore. Open ports are enriched with a banner grab,
mapped to a service/risk profile from a curated catalogue and aggregated into a 0-100 risk score.

Security policy: by default only private, loopback and link-local targets may be scanned. Public
targets must be enabled explicitly through ``Settings.scan_allow_public_targets``.
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import logging
import re
import socket
import statistics
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from app.config import Settings
from app.enums import PortState, RiskLevel
from app.schemas import PortFindingResult, PortScanOutcome

logger = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class ScanTargetError(ValueError):
    """Raised when a scan target or port selection is invalid, unresolvable or disallowed."""


@dataclass(frozen=True, slots=True)
class PortProfile:
    """Static knowledge about a TCP port: the usual service and the exposure risk it implies."""

    service: str
    risk_level: RiskLevel
    risk_reason: str
    recommendation: str


# ---------------------------------------------------------------------------
# Catalogue of commonly audited TCP ports
# ---------------------------------------------------------------------------

COMMON_PORTS: dict[int, PortProfile] = {
    20: PortProfile(
        "ftp-data",
        RiskLevel.HIGH,
        "FTP data channel is exposed; FTP transfers files and credentials in cleartext.",
        "Disable FTP and migrate to SFTP or FTPS; if FTP is unavoidable, restrict it to trusted hosts.",
    ),
    21: PortProfile(
        "ftp",
        RiskLevel.HIGH,
        "FTP sends credentials and file contents in cleartext and is a frequent brute-force target.",
        "Replace FTP with SFTP/FTPS, disable anonymous login and firewall the port from untrusted networks.",
    ),
    22: PortProfile(
        "ssh",
        RiskLevel.MEDIUM,
        "SSH is reachable; exposed remote administration is a constant brute-force target.",
        "Enforce key-based authentication, disable root login and password auth, and restrict sources with a firewall or VPN.",
    ),
    23: PortProfile(
        "telnet",
        RiskLevel.CRITICAL,
        "Telnet transmits credentials and sessions in cleartext and has no modern authentication.",
        "Disable the Telnet service immediately and use SSH for remote administration.",
    ),
    25: PortProfile(
        "smtp",
        RiskLevel.MEDIUM,
        "SMTP is exposed; open relays and user enumeration (VRFY/EXPN) can be abused for spam and recon.",
        "Disable open relaying, require STARTTLS and authentication, and limit access to mail gateways.",
    ),
    53: PortProfile(
        "dns",
        RiskLevel.LOW,
        "DNS over TCP is reachable; zone transfers or recursion may leak internal topology.",
        "Restrict zone transfers (AXFR) to secondary servers and disable recursion for untrusted clients.",
    ),
    80: PortProfile(
        "http",
        RiskLevel.MEDIUM,
        "Unencrypted HTTP is served; traffic and session cookies can be intercepted or tampered with.",
        "Redirect all traffic to HTTPS, enable HSTS and keep the web server and applications patched.",
    ),
    88: PortProfile(
        "kerberos",
        RiskLevel.LOW,
        "Kerberos KDC is reachable, which indicates an Active Directory domain controller.",
        "Restrict access to domain members and monitor for AS-REP roasting and Kerberoasting activity.",
    ),
    110: PortProfile(
        "pop3",
        RiskLevel.MEDIUM,
        "POP3 sends mailbox credentials in cleartext unless upgraded with STARTTLS.",
        "Move clients to POP3S (995) or IMAPS and disable the cleartext listener.",
    ),
    111: PortProfile(
        "rpcbind",
        RiskLevel.HIGH,
        "RPCbind/portmapper discloses registered RPC services (NFS, NIS) and has a history of amplification abuse.",
        "Disable rpcbind if NFS/NIS is not required, otherwise firewall it to trusted internal hosts.",
    ),
    135: PortProfile(
        "msrpc",
        RiskLevel.HIGH,
        "Microsoft RPC endpoint mapper is exposed and enables remote service enumeration and lateral movement.",
        "Block TCP 135 at the host and network firewall; never expose it beyond the management VLAN.",
    ),
    139: PortProfile(
        "netbios-ssn",
        RiskLevel.HIGH,
        "NetBIOS session service exposes legacy file sharing and host information leaks.",
        "Disable NetBIOS over TCP/IP and block ports 137-139 on all untrusted segments.",
    ),
    143: PortProfile(
        "imap",
        RiskLevel.MEDIUM,
        "IMAP may transmit credentials in cleartext unless STARTTLS is enforced.",
        "Require TLS (IMAPS on 993 or mandatory STARTTLS) and disable plaintext authentication.",
    ),
    389: PortProfile(
        "ldap",
        RiskLevel.HIGH,
        "Cleartext LDAP exposes directory data and allows credential interception and anonymous binds.",
        "Enforce LDAPS/StartTLS with signing, disable anonymous binds and restrict access to application servers.",
    ),
    443: PortProfile(
        "https",
        RiskLevel.LOW,
        "HTTPS is exposed; risk depends on TLS configuration and the application behind it.",
        "Use TLS 1.2+ only, keep certificates valid and patch the web stack regularly.",
    ),
    445: PortProfile(
        "smb",
        RiskLevel.CRITICAL,
        "SMB is exposed; it is the vector of EternalBlue/WannaCry-class wormable exploits and ransomware spread.",
        "Block TCP 445 from untrusted networks, disable SMBv1, enforce SMB signing and apply all security patches.",
    ),
    465: PortProfile(
        "smtps",
        RiskLevel.LOW,
        "SMTP over implicit TLS is exposed; mainly a credential brute-force surface.",
        "Require authentication, rate-limit logins and keep the mail server patched.",
    ),
    587: PortProfile(
        "submission",
        RiskLevel.LOW,
        "Mail submission port is exposed; mainly a credential brute-force surface.",
        "Require STARTTLS and authentication, rate-limit failed logins and monitor for relay abuse.",
    ),
    636: PortProfile(
        "ldaps",
        RiskLevel.LOW,
        "LDAP over TLS is exposed; directory data is protected in transit but still reachable.",
        "Restrict access to application servers and enforce strong certificates and bind policies.",
    ),
    993: PortProfile(
        "imaps",
        RiskLevel.LOW,
        "IMAP over TLS is exposed; mainly a credential brute-force surface.",
        "Enforce strong passwords with MFA or app passwords and rate-limit failed logins.",
    ),
    995: PortProfile(
        "pop3s",
        RiskLevel.LOW,
        "POP3 over TLS is exposed; mainly a credential brute-force surface.",
        "Enforce strong passwords with MFA or app passwords and rate-limit failed logins.",
    ),
    1433: PortProfile(
        "mssql",
        RiskLevel.HIGH,
        "Microsoft SQL Server is directly reachable, exposing the database to brute force and exploitation.",
        "Bind SQL Server to internal interfaces only, disable the sa account and firewall the port to application servers.",
    ),
    1521: PortProfile(
        "oracle",
        RiskLevel.HIGH,
        "Oracle TNS listener is exposed; it leaks SIDs and has a long history of listener vulnerabilities.",
        "Restrict the listener with valid-node checking, set a listener password and patch the database.",
    ),
    1883: PortProfile(
        "mqtt",
        RiskLevel.HIGH,
        "MQTT broker is reachable without TLS; anonymous brokers allow reading and publishing IoT messages.",
        "Require authentication and TLS (port 8883), define topic ACLs and disable anonymous access.",
    ),
    2049: PortProfile(
        "nfs",
        RiskLevel.HIGH,
        "NFS is exposed; misconfigured exports allow unauthenticated file access.",
        "Restrict exports to specific hosts, use root_squash and firewall NFS from untrusted networks.",
    ),
    2375: PortProfile(
        "docker-api",
        RiskLevel.CRITICAL,
        "Docker Engine API is exposed without TLS or authentication, granting root-equivalent control of the host.",
        "Disable the TCP listener or protect it with mutual TLS (2376) and restrict access to the management network.",
    ),
    2376: PortProfile(
        "docker-api-tls",
        RiskLevel.MEDIUM,
        "Docker Engine API over TLS is exposed; a compromised client certificate yields host-level control.",
        "Enforce mutual TLS with a private CA, rotate client certificates and limit access to management hosts.",
    ),
    3000: PortProfile(
        "dev-web",
        RiskLevel.MEDIUM,
        "A development web server (Node, Grafana, etc.) is listening and often runs without hardening.",
        "Do not expose development servers; place them behind a reverse proxy with authentication or shut them down.",
    ),
    3306: PortProfile(
        "mysql",
        RiskLevel.HIGH,
        "MySQL/MariaDB is directly reachable, exposing the database to brute force and exploitation.",
        "Bind the server to localhost or an internal interface, remove anonymous users and firewall the port.",
    ),
    3389: PortProfile(
        "rdp",
        RiskLevel.CRITICAL,
        "Remote Desktop is exposed; RDP is a primary ransomware entry point (BlueKeep, credential stuffing).",
        "Place RDP behind a VPN or RD Gateway, enable NLA and MFA, and block TCP 3389 from untrusted networks.",
    ),
    5000: PortProfile(
        "dev-web-alt",
        RiskLevel.MEDIUM,
        "A development service (Flask, UPnP, Docker registry) is listening and is often unauthenticated.",
        "Identify the owning process, disable it if unneeded or place it behind an authenticated reverse proxy.",
    ),
    5432: PortProfile(
        "postgresql",
        RiskLevel.HIGH,
        "PostgreSQL is directly reachable, exposing the database to brute force and exploitation.",
        "Limit listen_addresses, tighten pg_hba.conf to specific hosts and require scram-sha-256 authentication.",
    ),
    5672: PortProfile(
        "amqp",
        RiskLevel.MEDIUM,
        "AMQP message broker is exposed; default guest credentials allow queue access and message tampering.",
        "Remove default accounts, require TLS (5671) and restrict access to producer/consumer hosts.",
    ),
    5900: PortProfile(
        "vnc",
        RiskLevel.CRITICAL,
        "VNC is exposed; it often uses weak or no authentication and unencrypted screen sharing.",
        "Tunnel VNC through SSH or a VPN, enforce strong passwords and block the port from untrusted networks.",
    ),
    5985: PortProfile(
        "winrm",
        RiskLevel.HIGH,
        "WinRM over HTTP is exposed; it enables remote command execution with valid Windows credentials.",
        "Use WinRM over HTTPS (5986), restrict it to management hosts and enforce strong authentication.",
    ),
    5986: PortProfile(
        "winrm-https",
        RiskLevel.MEDIUM,
        "WinRM over HTTPS is exposed; it enables remote command execution with valid Windows credentials.",
        "Restrict access to management hosts, use certificate authentication and monitor remote sessions.",
    ),
    6379: PortProfile(
        "redis",
        RiskLevel.CRITICAL,
        "Redis is exposed; by default it has no authentication and can be abused for data theft and remote code execution.",
        "Bind to localhost, set requirepass or ACLs, enable protected mode and firewall port 6379.",
    ),
    8000: PortProfile(
        "http-alt",
        RiskLevel.MEDIUM,
        "An alternative HTTP service (often a development server) is listening, typically without TLS or hardening.",
        "Serve it over HTTPS behind a reverse proxy with authentication, or disable it if not required.",
    ),
    8080: PortProfile(
        "http-proxy",
        RiskLevel.MEDIUM,
        "An alternative HTTP service or proxy is listening, typically without TLS and with default consoles.",
        "Serve it over HTTPS, remove default admin consoles and restrict access to required clients.",
    ),
    8443: PortProfile(
        "https-alt",
        RiskLevel.LOW,
        "An alternative HTTPS service is exposed; management consoles frequently listen here.",
        "Restrict management interfaces to trusted networks and keep TLS configuration and software patched.",
    ),
    9090: PortProfile(
        "web-admin",
        RiskLevel.MEDIUM,
        "A management web interface (Prometheus, Cockpit, etc.) is listening and often lacks authentication.",
        "Enable authentication and TLS, or restrict the interface to the monitoring network.",
    ),
    9200: PortProfile(
        "elasticsearch",
        RiskLevel.HIGH,
        "Elasticsearch REST API is exposed; unauthenticated clusters leak and allow deletion of indexed data.",
        "Enable security features (authentication and TLS), bind to internal interfaces and firewall port 9200.",
    ),
    11211: PortProfile(
        "memcached",
        RiskLevel.HIGH,
        "Memcached is exposed without authentication, leaking cached data and enabling amplification attacks.",
        "Bind to localhost or an internal interface, enable SASL authentication and block the port externally.",
    ),
    27017: PortProfile(
        "mongodb",
        RiskLevel.CRITICAL,
        "MongoDB is exposed; unauthenticated instances have been mass-wiped and ransomed.",
        "Enable authentication and authorization, bind to internal interfaces and firewall port 27017.",
    ),
}

# ---------------------------------------------------------------------------
# Scoring and probing constants
# ---------------------------------------------------------------------------

RISK_WEIGHTS: dict[RiskLevel, int] = {
    RiskLevel.INFO: 0,
    RiskLevel.LOW: 5,
    RiskLevel.MEDIUM: 15,
    RiskLevel.HIGH: 30,
    RiskLevel.CRITICAL: 50,
}

_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.INFO: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

# TLS-wrapped services do not speak before the handshake, so a plaintext banner grab is pointless.
_TLS_PORTS: frozenset[int] = frozenset({443, 465, 636, 993, 995, 2376, 5986, 8443})
# Services that stay silent until the client sends an HTTP request.
_HTTP_PORTS: frozenset[int] = frozenset({80, 2375, 3000, 5000, 8000, 8080, 9090, 9200})
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"

_BANNER_READ_BYTES = 256
_BANNER_MAX_CHARS = 200
_BANNER_MAX_TIMEOUT = 1.0
_RESOLVE_TIMEOUT_SECONDS = 5.0
_LATENCY_SAMPLES = 3

# Connection-refused codes: POSIX ECONNREFUSED, Winsock WSAECONNREFUSED and Win32 ERROR_CONNECTION_REFUSED.
_REFUSED_CODES: frozenset[int] = frozenset({errno.ECONNREFUSED, 10061, 1225})

_HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}\.?$)[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})(\.[A-Za-z0-9_-]{1,63})*\.?$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_PING_TIME_PATTERN = re.compile(
    r"(?:time|tiempo|zeit|temps|tempo)\s*([=<])\s*(\d+(?:[.,]\d+)?)\s*(?:ms|m)?",
    re.IGNORECASE,
)
_OPENSSH_PATTERN = re.compile(r"OpenSSH_(\d+)\.(\d+)", re.IGNORECASE)
_APACHE_PATTERN = re.compile(r"Apache/(\d+)\.(\d+)", re.IGNORECASE)
_VSFTPD_BACKDOOR_PATTERN = re.compile(r"vsFTPd\s+2\.3\.4", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def calculate_risk_score(levels: Iterable[RiskLevel]) -> float:
    """Sum the per-finding weights and cap at 100, rounded to one decimal."""
    total = sum(RISK_WEIGHTS[level] for level in levels)
    return round(float(min(total, 100)), 1)


def highest_risk(levels: Iterable[RiskLevel]) -> RiskLevel:
    """Return the most severe level of the iterable, or INFO when it is empty."""
    return max(levels, key=_RISK_ORDER.__getitem__, default=RiskLevel.INFO)


def classify_connect_error(exc: OSError) -> PortState:
    """Map a failed TCP connect to a port state using POSIX and Winsock error codes.

    A refused connection means the host answered with a RST (port closed, host alive); every other
    failure (timeouts, unreachable networks, resets) is reported as filtered.
    """
    if isinstance(exc, ConnectionRefusedError):
        return PortState.CLOSED
    codes = {exc.errno, getattr(exc, "winerror", None)}
    if codes & _REFUSED_CODES:
        return PortState.CLOSED
    return PortState.FILTERED


def sanitize_banner(data: bytes) -> str | None:
    """Decode raw banner bytes into a short, printable single-line string (or None if unusable)."""
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    if text.count("�") / len(text) > 0.3:
        return None  # Binary protocol greeting; not meaningful as text.
    lines: list[str] = []
    for raw_line in text.splitlines():
        cleaned = " ".join(_CONTROL_CHARS.sub(" ", raw_line).split())
        if cleaned:
            lines.append(cleaned)
    banner = " | ".join(lines)[:_BANNER_MAX_CHARS].strip()
    return banner or None


def parse_ping_latency(output: str) -> float | None:
    """Extract the round-trip time in milliseconds from ``ping`` output (English or Spanish locales)."""
    match = _PING_TIME_PATTERN.search(output)
    if match is None:
        return None
    value = float(match.group(2).replace(",", "."))
    if match.group(1) == "<":
        # "time<1ms" only tells us the RTT is below the printed bound; report half of it.
        return round(value / 2, 3)
    return value


def _escalate(
    profile: PortProfile,
    level: RiskLevel,
    reason: str,
    recommendation: str,
    service: str | None = None,
) -> PortProfile:
    """Return a profile raised to at least ``level`` with extra context; never lowers the risk."""
    new_level = level if _RISK_ORDER[level] > _RISK_ORDER[profile.risk_level] else profile.risk_level
    new_service = service if service is not None and profile.service == "unknown" else profile.service
    return PortProfile(
        service=new_service,
        risk_level=new_level,
        risk_reason=f"{profile.risk_reason} {reason}",
        recommendation=f"{recommendation} {profile.recommendation}",
    )


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    """Close a stream writer, swallowing the errors a half-dead connection may raise."""
    try:
        writer.close()
        await writer.wait_closed()
    except OSError:
        pass
    except Exception:  # noqa: BLE001 - closing must never break the scan
        logger.debug("Ignoring error while closing connection", exc_info=True)


@dataclass(frozen=True, slots=True)
class _ProbeResult:
    port: int
    state: PortState
    response_ms: float | None
    banner: str | None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class NetworkScanner:
    """Concurrent TCP connect scanner with banner grabbing and risk classification."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    # -- Target resolution -------------------------------------------------

    async def resolve_target(self, target: str) -> str:
        """Validate ``target`` and return the IP address string that will be scanned.

        Raises ScanTargetError for empty/malformed targets, CIDR ranges, unresolvable names,
        multicast/unspecified/broadcast addresses and (unless enabled) public addresses.
        """
        candidate = target.strip() if isinstance(target, str) else ""
        if not candidate:
            raise ScanTargetError("Target must not be empty")
        if any(char.isspace() for char in candidate):
            raise ScanTargetError("Target must not contain whitespace; scan one host at a time")
        if "/" in candidate:
            raise ScanTargetError("CIDR ranges and URLs are not supported; provide a single host or IP address")

        literal = self._parse_ip_literal(candidate)
        if literal is not None:
            self._enforce_policy(literal)
            return str(literal)

        if not _HOSTNAME_PATTERN.match(candidate):
            raise ScanTargetError(f"'{candidate}' is not a valid IP address or hostname")

        addresses = await self._resolve_hostname(candidate)
        first_error: ScanTargetError | None = None
        for address in addresses:
            try:
                self._enforce_policy(address)
            except ScanTargetError as exc:
                first_error = first_error or exc
                continue
            return str(address)
        assert first_error is not None  # _resolve_hostname never returns an empty list
        raise ScanTargetError(f"Host '{candidate}' resolved only to disallowed addresses: {first_error}")

    @staticmethod
    def _parse_ip_literal(value: str) -> IPAddress | None:
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    async def _resolve_hostname(self, hostname: str) -> list[IPAddress]:
        """Resolve a hostname via ``getaddrinfo``, IPv4 results first, then IPv6."""
        loop = asyncio.get_running_loop()
        resolved: list[IPAddress] = []
        last_error: OSError | None = None
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(hostname, None, family=family, type=socket.SOCK_STREAM),
                    timeout=_RESOLVE_TIMEOUT_SECONDS,
                )
            except TimeoutError as exc:
                raise ScanTargetError(f"DNS resolution of '{hostname}' timed out") from exc
            except socket.gaierror as exc:
                last_error = exc
                continue
            for info in infos:
                address = self._parse_ip_literal(str(info[4][0]))
                if address is not None and address not in resolved:
                    resolved.append(address)
        if not resolved:
            detail = f": {last_error.strerror or last_error}" if last_error is not None else ""
            raise ScanTargetError(f"Cannot resolve host '{hostname}'{detail}")
        return resolved

    def _enforce_policy(self, address: IPAddress) -> None:
        """Apply the address-class and private-network scanning policy."""
        if address.is_unspecified:
            raise ScanTargetError(f"Unspecified address {address} cannot be scanned")
        if address.is_multicast:
            raise ScanTargetError(f"Multicast address {address} cannot be scanned")
        if address == ipaddress.IPv4Address("255.255.255.255"):
            raise ScanTargetError("Broadcast address cannot be scanned")
        if self._settings.scan_allow_public_targets:
            return
        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise ScanTargetError(
                f"{address} is a public address; only private, loopback and link-local targets are "
                "allowed (set NETPULSE_SCAN_ALLOW_PUBLIC_TARGETS=true to override)"
            )

    # -- Classification ----------------------------------------------------

    def classify_port(self, port: int, banner: str | None = None) -> PortProfile:
        """Return the risk profile for ``port``, adjusted by the service banner when it reveals weaknesses."""
        profile = COMMON_PORTS.get(port)
        if profile is None:
            if port < 1024:
                profile = PortProfile(
                    service="unknown",
                    risk_level=RiskLevel.MEDIUM,
                    risk_reason="An unrecognised service is listening on a privileged port (<1024).",
                    recommendation="Identify the owning process, disable the service if it is not required and firewall the port.",
                )
            else:
                profile = PortProfile(
                    service="unknown",
                    risk_level=RiskLevel.LOW,
                    risk_reason="An unrecognised service is listening on a high port.",
                    recommendation="Verify the service is expected, keep it patched and restrict access to required clients.",
                )
        if not banner:
            return profile

        if _VSFTPD_BACKDOOR_PATTERN.search(banner):
            profile = _escalate(
                profile,
                RiskLevel.CRITICAL,
                "Banner reveals vsFTPd 2.3.4, a release shipped with a malicious backdoor (CVE-2011-2523).",
                "Remove this vsFTPd build immediately, reinstall from a trusted source and investigate for compromise.",
                service="ftp",
            )

        ssh_match = _OPENSSH_PATTERN.search(banner)
        if ssh_match is not None and int(ssh_match.group(1)) < 8:
            version = f"{ssh_match.group(1)}.{ssh_match.group(2)}"
            profile = _escalate(
                profile,
                RiskLevel.HIGH,
                f"Banner reveals OpenSSH {version}, an outdated release with known vulnerabilities.",
                "Upgrade OpenSSH to a supported release (8.x or newer).",
                service="ssh",
            )

        apache_match = _APACHE_PATTERN.search(banner)
        if apache_match is not None and (int(apache_match.group(1)), int(apache_match.group(2))) <= (2, 2):
            version = f"{apache_match.group(1)}.{apache_match.group(2)}"
            profile = _escalate(
                profile,
                RiskLevel.HIGH,
                f"Banner reveals Apache {version}, an end-of-life release that no longer receives security fixes.",
                "Upgrade Apache httpd to a supported 2.4.x release.",
                service="http",
            )
        return profile

    # -- Scanning ----------------------------------------------------------

    async def scan(
        self,
        target: str,
        ports: list[int] | None = None,
        *,
        timeout: float | None = None,
        concurrency: int | None = None,
        grab_banners: bool | None = None,
    ) -> PortScanOutcome:
        """Scan ``target`` and return a pure result object (no persistence)."""
        settings = self._settings
        effective_timeout = timeout if timeout is not None else settings.scan_default_timeout_seconds
        effective_concurrency = concurrency if concurrency is not None else settings.scan_max_concurrency
        effective_banners = grab_banners if grab_banners is not None else settings.scan_banner_grab
        if effective_timeout <= 0:
            raise ScanTargetError("Timeout must be greater than zero")
        if effective_concurrency < 1:
            raise ScanTargetError("Concurrency must be at least 1")

        port_list = self._normalise_ports(ports)

        started_at = datetime.now(UTC)
        clock_start = time.perf_counter()
        ip = await self.resolve_target(target)
        logger.info("Starting scan of %s (%s): %d ports", target, ip, len(port_list))

        semaphore = asyncio.Semaphore(min(effective_concurrency, len(port_list)))
        results = await asyncio.gather(
            *(self._probe_port(ip, port, effective_timeout, effective_banners, semaphore) for port in port_list)
        )

        open_results = sorted((r for r in results if r.state is PortState.OPEN), key=lambda r: r.port)
        any_closed = any(r.state is PortState.CLOSED for r in results)

        host_latency_ms: float | None = None
        if open_results:
            host_latency_ms = await self._measure_tcp_rtt(ip, open_results[0].port, effective_timeout)
        ping_ok = False
        if host_latency_ms is None:
            ping_latency = await self._icmp_ping(ip, effective_timeout)
            if ping_latency is not None:
                ping_ok = True
                host_latency_ms = ping_latency
        host_reachable = bool(open_results) or any_closed or ping_ok

        findings: list[PortFindingResult] = []
        for result in open_results:
            profile = self.classify_port(result.port, result.banner)
            findings.append(
                PortFindingResult(
                    port=result.port,
                    service=profile.service,
                    state=PortState.OPEN,
                    banner=result.banner,
                    response_ms=result.response_ms,
                    risk_level=profile.risk_level,
                    risk_reason=profile.risk_reason,
                    recommendation=profile.recommendation,
                )
            )

        levels = [finding.risk_level for finding in findings]
        finished_at = datetime.now(UTC)
        duration_ms = round((time.perf_counter() - clock_start) * 1000, 2)
        outcome = PortScanOutcome(
            target_host=target.strip(),
            resolved_ip=ip,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            host_reachable=host_reachable,
            host_latency_ms=host_latency_ms,
            total_ports_scanned=len(port_list),
            open_ports_count=len(findings),
            risk_score=calculate_risk_score(levels),
            overall_risk=highest_risk(levels),
            findings=findings,
        )
        logger.info(
            "Scan of %s finished in %.1f ms: %d open, risk %s (score %.1f)",
            ip,
            duration_ms,
            outcome.open_ports_count,
            outcome.overall_risk.value,
            outcome.risk_score,
        )
        return outcome

    def _normalise_ports(self, ports: list[int] | None) -> list[int]:
        """Validate, de-duplicate and sort the requested ports (default: the common-port catalogue)."""
        if ports is None:
            return sorted(COMMON_PORTS)
        if not ports:
            raise ScanTargetError("At least one port must be provided")
        for port in ports:
            if not 1 <= port <= 65535:
                raise ScanTargetError(f"Port {port} is outside the valid range 1-65535")
        unique = sorted(set(ports))
        if len(unique) > self._settings.scan_max_ports:
            raise ScanTargetError(
                f"Too many ports requested ({len(unique)}); the maximum per scan is {self._settings.scan_max_ports}"
            )
        return unique

    async def _probe_port(
        self,
        ip: str,
        port: int,
        timeout: float,
        grab_banner: bool,
        semaphore: asyncio.Semaphore,
    ) -> _ProbeResult:
        """Probe a single port: connect, time the handshake and optionally grab a banner."""
        async with semaphore:
            started = time.perf_counter()
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            except TimeoutError:
                return _ProbeResult(port, PortState.FILTERED, None, None)
            except OSError as exc:
                state = classify_connect_error(exc)
                logger.debug("Port %d on %s: %s (%s)", port, ip, state.value, exc)
                return _ProbeResult(port, state, None, None)

            response_ms = round((time.perf_counter() - started) * 1000, 2)
            banner: str | None = None
            try:
                if grab_banner:
                    banner = await self._grab_banner(reader, writer, port, timeout)
            finally:
                await _close_writer(writer)
            return _ProbeResult(port, PortState.OPEN, response_ms, banner)

    @staticmethod
    async def _grab_banner(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
        timeout: float,
    ) -> str | None:
        """Read up to 256 bytes from an open connection, speaking HEAD first on plain-HTTP ports."""
        if port in _TLS_PORTS:
            return None
        read_timeout = min(timeout, _BANNER_MAX_TIMEOUT)
        try:
            if port in _HTTP_PORTS:
                writer.write(_HTTP_PROBE)
                await asyncio.wait_for(writer.drain(), timeout=read_timeout)
            data = await asyncio.wait_for(reader.read(_BANNER_READ_BYTES), timeout=read_timeout)
        except (TimeoutError, OSError):
            return None
        return sanitize_banner(data)

    # -- Host latency ------------------------------------------------------

    async def _measure_tcp_rtt(self, ip: str, port: int, timeout: float) -> float | None:
        """Median TCP connect round-trip time (ms) over several fresh connections to an open port."""
        samples: list[float] = []
        for _ in range(_LATENCY_SAMPLES):
            started = time.perf_counter()
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            except (TimeoutError, OSError):
                continue
            samples.append((time.perf_counter() - started) * 1000)
            await _close_writer(writer)
        if not samples:
            return None
        return round(statistics.median(samples), 2)

    async def _icmp_ping(self, ip: str, timeout: float) -> float | None:
        """Send one system ICMP echo request and return its RTT in ms, or None on any failure."""
        wait = max(timeout, 1.0)
        if sys.platform == "win32":
            command = ["ping", "-n", "1", "-w", str(int(wait * 1000)), ip]
        else:
            command = ["ping", "-c", "1", "-W", str(max(1, int(wait))), ip]
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except (OSError, NotImplementedError):
            logger.debug("System ping is not available", exc_info=True)
            return None
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=wait + 2.0)
        except TimeoutError:
            process.kill()
            await process.wait()
            return None
        # Windows reports "host unreachable" with exit code 0, so require a parsable time as well.
        if process.returncode != 0:
            return None
        return parse_ping_latency(stdout.decode("utf-8", errors="replace"))
