/**
 * Catalogue of commonly audited TCP ports, banner-driven risk escalation and risk scoring.
 * A faithful port of the pure parts of backend/app/services/network_scanner.py.
 */

import type { RiskLevel } from "../../types/api";

export interface PortProfile {
  service: string;
  riskLevel: RiskLevel;
  riskReason: string;
  recommendation: string;
}

function profile(service: string, riskLevel: RiskLevel, riskReason: string, recommendation: string): PortProfile {
  return { service, riskLevel, riskReason, recommendation };
}

export const COMMON_PORTS: ReadonlyMap<number, PortProfile> = new Map<number, PortProfile>([
  [
    20,
    profile(
      "ftp-data",
      "high",
      "FTP data channel is exposed; FTP transfers files and credentials in cleartext.",
      "Disable FTP and migrate to SFTP or FTPS; if FTP is unavoidable, restrict it to trusted hosts.",
    ),
  ],
  [
    21,
    profile(
      "ftp",
      "high",
      "FTP sends credentials and file contents in cleartext and is a frequent brute-force target.",
      "Replace FTP with SFTP/FTPS, disable anonymous login and firewall the port from untrusted networks.",
    ),
  ],
  [
    22,
    profile(
      "ssh",
      "medium",
      "SSH is reachable; exposed remote administration is a constant brute-force target.",
      "Enforce key-based authentication, disable root login and password auth, and restrict sources with a firewall or VPN.",
    ),
  ],
  [
    23,
    profile(
      "telnet",
      "critical",
      "Telnet transmits credentials and sessions in cleartext and has no modern authentication.",
      "Disable the Telnet service immediately and use SSH for remote administration.",
    ),
  ],
  [
    25,
    profile(
      "smtp",
      "medium",
      "SMTP is exposed; open relays and user enumeration (VRFY/EXPN) can be abused for spam and recon.",
      "Disable open relaying, require STARTTLS and authentication, and limit access to mail gateways.",
    ),
  ],
  [
    53,
    profile(
      "dns",
      "low",
      "DNS over TCP is reachable; zone transfers or recursion may leak internal topology.",
      "Restrict zone transfers (AXFR) to secondary servers and disable recursion for untrusted clients.",
    ),
  ],
  [
    80,
    profile(
      "http",
      "medium",
      "Unencrypted HTTP is served; traffic and session cookies can be intercepted or tampered with.",
      "Redirect all traffic to HTTPS, enable HSTS and keep the web server and applications patched.",
    ),
  ],
  [
    88,
    profile(
      "kerberos",
      "low",
      "Kerberos KDC is reachable, which indicates an Active Directory domain controller.",
      "Restrict access to domain members and monitor for AS-REP roasting and Kerberoasting activity.",
    ),
  ],
  [
    110,
    profile(
      "pop3",
      "medium",
      "POP3 sends mailbox credentials in cleartext unless upgraded with STARTTLS.",
      "Move clients to POP3S (995) or IMAPS and disable the cleartext listener.",
    ),
  ],
  [
    111,
    profile(
      "rpcbind",
      "high",
      "RPCbind/portmapper discloses registered RPC services (NFS, NIS) and has a history of amplification abuse.",
      "Disable rpcbind if NFS/NIS is not required, otherwise firewall it to trusted internal hosts.",
    ),
  ],
  [
    135,
    profile(
      "msrpc",
      "high",
      "Microsoft RPC endpoint mapper is exposed and enables remote service enumeration and lateral movement.",
      "Block TCP 135 at the host and network firewall; never expose it beyond the management VLAN.",
    ),
  ],
  [
    139,
    profile(
      "netbios-ssn",
      "high",
      "NetBIOS session service exposes legacy file sharing and host information leaks.",
      "Disable NetBIOS over TCP/IP and block ports 137-139 on all untrusted segments.",
    ),
  ],
  [
    143,
    profile(
      "imap",
      "medium",
      "IMAP may transmit credentials in cleartext unless STARTTLS is enforced.",
      "Require TLS (IMAPS on 993 or mandatory STARTTLS) and disable plaintext authentication.",
    ),
  ],
  [
    389,
    profile(
      "ldap",
      "high",
      "Cleartext LDAP exposes directory data and allows credential interception and anonymous binds.",
      "Enforce LDAPS/StartTLS with signing, disable anonymous binds and restrict access to application servers.",
    ),
  ],
  [
    443,
    profile(
      "https",
      "low",
      "HTTPS is exposed; risk depends on TLS configuration and the application behind it.",
      "Use TLS 1.2+ only, keep certificates valid and patch the web stack regularly.",
    ),
  ],
  [
    445,
    profile(
      "smb",
      "critical",
      "SMB is exposed; it is the vector of EternalBlue/WannaCry-class wormable exploits and ransomware spread.",
      "Block TCP 445 from untrusted networks, disable SMBv1, enforce SMB signing and apply all security patches.",
    ),
  ],
  [
    465,
    profile(
      "smtps",
      "low",
      "SMTP over implicit TLS is exposed; mainly a credential brute-force surface.",
      "Require authentication, rate-limit logins and keep the mail server patched.",
    ),
  ],
  [
    587,
    profile(
      "submission",
      "low",
      "Mail submission port is exposed; mainly a credential brute-force surface.",
      "Require STARTTLS and authentication, rate-limit failed logins and monitor for relay abuse.",
    ),
  ],
  [
    636,
    profile(
      "ldaps",
      "low",
      "LDAP over TLS is exposed; directory data is protected in transit but still reachable.",
      "Restrict access to application servers and enforce strong certificates and bind policies.",
    ),
  ],
  [
    993,
    profile(
      "imaps",
      "low",
      "IMAP over TLS is exposed; mainly a credential brute-force surface.",
      "Enforce strong passwords with MFA or app passwords and rate-limit failed logins.",
    ),
  ],
  [
    995,
    profile(
      "pop3s",
      "low",
      "POP3 over TLS is exposed; mainly a credential brute-force surface.",
      "Enforce strong passwords with MFA or app passwords and rate-limit failed logins.",
    ),
  ],
  [
    1433,
    profile(
      "mssql",
      "high",
      "Microsoft SQL Server is directly reachable, exposing the database to brute force and exploitation.",
      "Bind SQL Server to internal interfaces only, disable the sa account and firewall the port to application servers.",
    ),
  ],
  [
    1521,
    profile(
      "oracle",
      "high",
      "Oracle TNS listener is exposed; it leaks SIDs and has a long history of listener vulnerabilities.",
      "Restrict the listener with valid-node checking, set a listener password and patch the database.",
    ),
  ],
  [
    1883,
    profile(
      "mqtt",
      "high",
      "MQTT broker is reachable without TLS; anonymous brokers allow reading and publishing IoT messages.",
      "Require authentication and TLS (port 8883), define topic ACLs and disable anonymous access.",
    ),
  ],
  [
    2049,
    profile(
      "nfs",
      "high",
      "NFS is exposed; misconfigured exports allow unauthenticated file access.",
      "Restrict exports to specific hosts, use root_squash and firewall NFS from untrusted networks.",
    ),
  ],
  [
    2375,
    profile(
      "docker-api",
      "critical",
      "Docker Engine API is exposed without TLS or authentication, granting root-equivalent control of the host.",
      "Disable the TCP listener or protect it with mutual TLS (2376) and restrict access to the management network.",
    ),
  ],
  [
    2376,
    profile(
      "docker-api-tls",
      "medium",
      "Docker Engine API over TLS is exposed; a compromised client certificate yields host-level control.",
      "Enforce mutual TLS with a private CA, rotate client certificates and limit access to management hosts.",
    ),
  ],
  [
    3000,
    profile(
      "dev-web",
      "medium",
      "A development web server (Node, Grafana, etc.) is listening and often runs without hardening.",
      "Do not expose development servers; place them behind a reverse proxy with authentication or shut them down.",
    ),
  ],
  [
    3306,
    profile(
      "mysql",
      "high",
      "MySQL/MariaDB is directly reachable, exposing the database to brute force and exploitation.",
      "Bind the server to localhost or an internal interface, remove anonymous users and firewall the port.",
    ),
  ],
  [
    3389,
    profile(
      "rdp",
      "critical",
      "Remote Desktop is exposed; RDP is a primary ransomware entry point (BlueKeep, credential stuffing).",
      "Place RDP behind a VPN or RD Gateway, enable NLA and MFA, and block TCP 3389 from untrusted networks.",
    ),
  ],
  [
    5000,
    profile(
      "dev-web-alt",
      "medium",
      "A development service (Flask, UPnP, Docker registry) is listening and is often unauthenticated.",
      "Identify the owning process, disable it if unneeded or place it behind an authenticated reverse proxy.",
    ),
  ],
  [
    5432,
    profile(
      "postgresql",
      "high",
      "PostgreSQL is directly reachable, exposing the database to brute force and exploitation.",
      "Limit listen_addresses, tighten pg_hba.conf to specific hosts and require scram-sha-256 authentication.",
    ),
  ],
  [
    5672,
    profile(
      "amqp",
      "medium",
      "AMQP message broker is exposed; default guest credentials allow queue access and message tampering.",
      "Remove default accounts, require TLS (5671) and restrict access to producer/consumer hosts.",
    ),
  ],
  [
    5900,
    profile(
      "vnc",
      "critical",
      "VNC is exposed; it often uses weak or no authentication and unencrypted screen sharing.",
      "Tunnel VNC through SSH or a VPN, enforce strong passwords and block the port from untrusted networks.",
    ),
  ],
  [
    5985,
    profile(
      "winrm",
      "high",
      "WinRM over HTTP is exposed; it enables remote command execution with valid Windows credentials.",
      "Use WinRM over HTTPS (5986), restrict it to management hosts and enforce strong authentication.",
    ),
  ],
  [
    5986,
    profile(
      "winrm-https",
      "medium",
      "WinRM over HTTPS is exposed; it enables remote command execution with valid Windows credentials.",
      "Restrict access to management hosts, use certificate authentication and monitor remote sessions.",
    ),
  ],
  [
    6379,
    profile(
      "redis",
      "critical",
      "Redis is exposed; by default it has no authentication and can be abused for data theft and remote code execution.",
      "Bind to localhost, set requirepass or ACLs, enable protected mode and firewall port 6379.",
    ),
  ],
  [
    8000,
    profile(
      "http-alt",
      "medium",
      "An alternative HTTP service (often a development server) is listening, typically without TLS or hardening.",
      "Serve it over HTTPS behind a reverse proxy with authentication, or disable it if not required.",
    ),
  ],
  [
    8080,
    profile(
      "http-proxy",
      "medium",
      "An alternative HTTP service or proxy is listening, typically without TLS and with default consoles.",
      "Serve it over HTTPS, remove default admin consoles and restrict access to required clients.",
    ),
  ],
  [
    8443,
    profile(
      "https-alt",
      "low",
      "An alternative HTTPS service is exposed; management consoles frequently listen here.",
      "Restrict management interfaces to trusted networks and keep TLS configuration and software patched.",
    ),
  ],
  [
    9090,
    profile(
      "web-admin",
      "medium",
      "A management web interface (Prometheus, Cockpit, etc.) is listening and often lacks authentication.",
      "Enable authentication and TLS, or restrict the interface to the monitoring network.",
    ),
  ],
  [
    9200,
    profile(
      "elasticsearch",
      "high",
      "Elasticsearch REST API is exposed; unauthenticated clusters leak and allow deletion of indexed data.",
      "Enable security features (authentication and TLS), bind to internal interfaces and firewall port 9200.",
    ),
  ],
  [
    11211,
    profile(
      "memcached",
      "high",
      "Memcached is exposed without authentication, leaking cached data and enabling amplification attacks.",
      "Bind to localhost or an internal interface, enable SASL authentication and block the port externally.",
    ),
  ],
  [
    27017,
    profile(
      "mongodb",
      "critical",
      "MongoDB is exposed; unauthenticated instances have been mass-wiped and ransomed.",
      "Enable authentication and authorization, bind to internal interfaces and firewall port 27017.",
    ),
  ],
]);

/** Ports audited when a request names none: the whole catalogue, ascending. */
export const DEFAULT_SCAN_PORTS: readonly number[] = [...COMMON_PORTS.keys()].sort((a, b) => a - b);

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

export const RISK_WEIGHTS: Readonly<Record<RiskLevel, number>> = {
  info: 0,
  low: 5,
  medium: 15,
  high: 30,
  critical: 50,
};

const RISK_ORDER: Readonly<Record<RiskLevel, number>> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Sum the per-finding weights and cap at 100, rounded to one decimal. */
export function calculateRiskScore(levels: Iterable<RiskLevel>): number {
  let total = 0;
  for (const level of levels) {
    total += RISK_WEIGHTS[level];
  }
  return Math.round(Math.min(total, 100) * 10) / 10;
}

/** Most severe level of the iterable, or "info" when it is empty. */
export function highestRisk(levels: Iterable<RiskLevel>): RiskLevel {
  let best: RiskLevel = "info";
  for (const level of levels) {
    if (RISK_ORDER[level] > RISK_ORDER[best]) {
      best = level;
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// Banner-driven classification
// ---------------------------------------------------------------------------

/** TLS-wrapped services do not speak before the handshake, so a plaintext banner grab is pointless. */
export const TLS_PORTS: ReadonlySet<number> = new Set([443, 465, 636, 993, 995, 2376, 5986, 8443]);
/** Services that stay silent until the client sends an HTTP request. */
export const HTTP_PORTS: ReadonlySet<number> = new Set([80, 2375, 3000, 5000, 8000, 8080, 9090, 9200]);

const OPENSSH_PATTERN = /OpenSSH_(\d+)\.(\d+)/i;
const APACHE_PATTERN = /Apache\/(\d+)\.(\d+)/i;
const VSFTPD_BACKDOOR_PATTERN = /vsFTPd\s+2\.3\.4/i;

/** Return a profile raised to at least `level` with extra context; never lowers the risk. */
function escalate(
  base: PortProfile,
  level: RiskLevel,
  reason: string,
  recommendation: string,
  service?: string,
): PortProfile {
  const newLevel = RISK_ORDER[level] > RISK_ORDER[base.riskLevel] ? level : base.riskLevel;
  const newService = service !== undefined && base.service === "unknown" ? service : base.service;
  return {
    service: newService,
    riskLevel: newLevel,
    riskReason: `${base.riskReason} ${reason}`,
    recommendation: `${recommendation} ${base.recommendation}`,
  };
}

/** Risk profile for `port`, adjusted by the service banner when it reveals known weaknesses. */
export function classifyPort(port: number, banner: string | null = null): PortProfile {
  let result = COMMON_PORTS.get(port);
  if (result === undefined) {
    result =
      port < 1024
        ? {
            service: "unknown",
            riskLevel: "medium",
            riskReason: "An unrecognised service is listening on a privileged port (<1024).",
            recommendation:
              "Identify the owning process, disable the service if it is not required and firewall the port.",
          }
        : {
            service: "unknown",
            riskLevel: "low",
            riskReason: "An unrecognised service is listening on a high port.",
            recommendation:
              "Verify the service is expected, keep it patched and restrict access to required clients.",
          };
  }
  if (banner === null || banner === "") {
    return result;
  }

  if (VSFTPD_BACKDOOR_PATTERN.test(banner)) {
    result = escalate(
      result,
      "critical",
      "Banner reveals vsFTPd 2.3.4, a release shipped with a malicious backdoor (CVE-2011-2523).",
      "Remove this vsFTPd build immediately, reinstall from a trusted source and investigate for compromise.",
      "ftp",
    );
  }

  const ssh = OPENSSH_PATTERN.exec(banner);
  if (ssh !== null && Number(ssh[1]) < 8) {
    result = escalate(
      result,
      "high",
      `Banner reveals OpenSSH ${ssh[1]}.${ssh[2]}, an outdated release with known vulnerabilities.`,
      "Upgrade OpenSSH to a supported release (8.x or newer).",
      "ssh",
    );
  }

  const apache = APACHE_PATTERN.exec(banner);
  if (apache !== null) {
    const major = Number(apache[1]);
    const minor = Number(apache[2]);
    if (major < 2 || (major === 2 && minor <= 2)) {
      result = escalate(
        result,
        "high",
        `Banner reveals Apache ${major}.${minor}, an end-of-life release that no longer receives security fixes.`,
        "Upgrade Apache httpd to a supported 2.4.x release.",
        "http",
      );
    }
  }
  return result;
}
