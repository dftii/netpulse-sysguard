/**
 * Simulated port auditor. It applies the same target policy, port validation, banner handling and
 * risk scoring as backend/app/services/network_scanner.py, but instead of opening sockets it
 * answers from per-host service profiles:
 *
 *  - the eight simulated enterprise nodes expose the services their role implies (including a few
 *    deliberate exposures: Redis, Telnet, SMB and a backdoored vsFTPd), and an outage injected on a
 *    node makes it unreachable for scans as well;
 *  - any other private address gets a pseudo-random device profile (router, camera, printer,
 *    workstation, server...) that is deterministic for that address;
 *  - public addresses and unresolvable names are rejected exactly like the backend does.
 */

import type { PortScanRequest, RiskLevel } from "../../types/api";
import { SourceError } from "../telemetrySource";
import {
  calculateRiskScore,
  classifyPort,
  DEFAULT_SCAN_PORTS,
  HTTP_PORTS,
  highestRisk,
  TLS_PORTS,
} from "./portCatalog";
import { NODE_PROFILES, profileByHostname, profileByIp, type NodeProfile } from "./profiles";
import { hashString, Random } from "./random";

/** Maximum number of ports one request may audit (backend `scan_max_ports`). */
export const SCAN_MAX_PORTS = 1024;
/** Scans that may run at the same time before the backend answers 429. */
export const MAX_CONCURRENT_SCANS = 2;

const MIN_SCAN_DELAY_MS = 1500;
const MAX_SCAN_DELAY_MS = 4000;
const UNREACHABLE_EXTRA_DELAY_MS = 600;
const MAX_TARGET_LENGTH = 255;
const MAX_TIMEOUT_SECONDS = 10;
const MAX_CONCURRENCY = 2000;

const HOSTNAME_PATTERN = /^(?=.{1,253}\.?$)[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})(\.[A-Za-z0-9_-]{1,63})*\.?$/;

// ---------------------------------------------------------------------------
// Target parsing and policy
// ---------------------------------------------------------------------------

type Ipv4 = readonly [number, number, number, number];

function parseIpv4(value: string): Ipv4 | null {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    return null;
  }
  const octets = value.split(".").map((part) => (part.length > 1 && part.startsWith("0") ? Number.NaN : Number(part)));
  if (octets.some((octet) => !Number.isInteger(octet) || octet > 255)) {
    return null;
  }
  const [a, b, c, d] = octets;
  if (a === undefined || b === undefined || c === undefined || d === undefined) {
    return null;
  }
  return [a, b, c, d];
}

/** Parse an IPv6 literal (no zone id) into eight 16-bit groups. */
function parseIpv6(value: string): number[] | null {
  if (!/^[0-9a-fA-F:.]+$/.test(value) || !value.includes(":")) {
    return null;
  }
  let text = value;
  const lastColon = text.lastIndexOf(":");
  const tail = text.slice(lastColon + 1);
  if (tail.includes(".")) {
    const embedded = parseIpv4(tail);
    if (embedded === null) {
      return null;
    }
    const high = ((embedded[0] << 8) | embedded[1]).toString(16);
    const low = ((embedded[2] << 8) | embedded[3]).toString(16);
    text = `${text.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) {
    return null;
  }
  const parseGroups = (part: string): number[] | null => {
    if (part === "") {
      return [];
    }
    const groups: number[] = [];
    for (const piece of part.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) {
        return null;
      }
      groups.push(Number.parseInt(piece, 16));
    }
    return groups;
  };
  const head = parseGroups(halves[0] ?? "");
  if (head === null) {
    return null;
  }
  if (halves.length === 1) {
    return head.length === 8 ? head : null;
  }
  const rest = parseGroups(halves[1] ?? "");
  if (rest === null || head.length + rest.length > 7) {
    return null;
  }
  return [...head, ...new Array<number>(8 - head.length - rest.length).fill(0), ...rest];
}

/** Canonical (compressed, lower-case) text form of an IPv6 address. */
function formatIpv6(groups: readonly number[]): string {
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  for (let index = 0; index <= groups.length; index += 1) {
    if (index < groups.length && groups[index] === 0) {
      if (runStart === -1) {
        runStart = index;
      }
    } else if (runStart !== -1) {
      if (index - runStart > bestLength) {
        bestStart = runStart;
        bestLength = index - runStart;
      }
      runStart = -1;
    }
  }
  const text = (slice: readonly number[]): string => slice.map((group) => group.toString(16)).join(":");
  if (bestLength < 2) {
    return text(groups);
  }
  return `${text(groups.slice(0, bestStart))}::${text(groups.slice(bestStart + bestLength))}`;
}

function inRange(address: Ipv4, base: Ipv4, prefixBits: number): boolean {
  const toInt = (octets: Ipv4): number => ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = prefixBits === 0 ? 0 : (0xffffffff << (32 - prefixBits)) >>> 0;
  return (toInt(address) & mask) === (toInt(base) & mask);
}

/** Ranges Python's ipaddress treats as private (RFC 1918, special-purpose and documentation blocks). */
const IPV4_PRIVATE_RANGES: readonly (readonly [Ipv4, number])[] = [
  [[0, 0, 0, 0], 8],
  [[10, 0, 0, 0], 8],
  [[127, 0, 0, 0], 8],
  [[169, 254, 0, 0], 16],
  [[172, 16, 0, 0], 12],
  [[192, 0, 0, 0], 29],
  [[192, 0, 0, 170], 31],
  [[192, 0, 2, 0], 24],
  [[192, 168, 0, 0], 16],
  [[198, 18, 0, 0], 15],
  [[198, 51, 100, 0], 24],
  [[203, 0, 113, 0], 24],
  [[240, 0, 0, 0], 4],
];

function enforceIpv4Policy(address: Ipv4): void {
  const text = address.join(".");
  if (address.every((octet) => octet === 0)) {
    throw new SourceError(`Unspecified address ${text} cannot be scanned`, 400);
  }
  if (inRange(address, [224, 0, 0, 0], 4)) {
    throw new SourceError(`Multicast address ${text} cannot be scanned`, 400);
  }
  if (address.every((octet) => octet === 255)) {
    throw new SourceError("Broadcast address cannot be scanned", 400);
  }
  const allowed = IPV4_PRIVATE_RANGES.some(([base, bits]) => inRange(address, base, bits));
  if (!allowed) {
    throw new SourceError(
      `${text} is a public address; only private, loopback and link-local targets are allowed`,
      400,
    );
  }
}

function enforceIpv6Policy(groups: readonly number[]): void {
  const text = formatIpv6(groups);
  const first = groups[0] ?? 0;
  const isLoopback = groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1;
  if (groups.every((group) => group === 0)) {
    throw new SourceError(`Unspecified address ${text} cannot be scanned`, 400);
  }
  if ((first & 0xff00) === 0xff00) {
    throw new SourceError(`Multicast address ${text} cannot be scanned`, 400);
  }
  const isLinkLocal = (first & 0xffc0) === 0xfe80;
  const isUniqueLocal = (first & 0xfe00) === 0xfc00;
  const isDocumentation = first === 0x2001 && groups[1] === 0x0db8;
  if (!(isLoopback || isLinkLocal || isUniqueLocal || isDocumentation)) {
    throw new SourceError(
      `${text} is a public address; only private, loopback and link-local targets are allowed`,
      400,
    );
  }
}

export interface ResolvedTarget {
  /** IP address that will be audited, in canonical text form. */
  ip: string;
  /** Simulated enterprise node behind the address, when there is one. */
  node: NodeProfile | undefined;
  /** True for 127.0.0.0/8 and ::1. */
  loopback: boolean;
}

/**
 * Validate `target` and return the address that will be audited. Raises SourceError(400) for
 * empty/malformed targets, CIDR ranges, unresolvable names, multicast/unspecified/broadcast
 * addresses and public addresses.
 */
export function resolveTarget(target: string): ResolvedTarget {
  const candidate = typeof target === "string" ? target.trim() : "";
  if (candidate === "") {
    throw new SourceError("Target must not be empty", 400);
  }
  if (candidate.length > MAX_TARGET_LENGTH) {
    throw new SourceError(`Target must be at most ${MAX_TARGET_LENGTH} characters`, 422);
  }
  if (/\s/.test(candidate)) {
    throw new SourceError("Target must not contain whitespace; scan one host at a time", 400);
  }
  if (candidate.includes("/")) {
    throw new SourceError("CIDR ranges and URLs are not supported; provide a single host or IP address", 400);
  }

  const v4 = parseIpv4(candidate);
  if (v4 !== null) {
    enforceIpv4Policy(v4);
    const ip = v4.join(".");
    return { ip, node: profileByIp(ip), loopback: v4[0] === 127 };
  }
  const v6 = parseIpv6(candidate);
  if (v6 !== null) {
    enforceIpv6Policy(v6);
    const loopback = v6.slice(0, 7).every((group) => group === 0) && v6[7] === 1;
    return { ip: formatIpv6(v6), node: undefined, loopback };
  }

  if (!HOSTNAME_PATTERN.test(candidate)) {
    throw new SourceError(`'${candidate}' is not a valid IP address or hostname`, 400);
  }
  const name = candidate.toLowerCase().replace(/\.$/, "");
  if (name === "localhost") {
    return { ip: "127.0.0.1", node: undefined, loopback: true };
  }
  const node = profileByHostname(name);
  if (node === undefined) {
    throw new SourceError(`Cannot resolve host '${candidate}': Name or service not known`, 400);
  }
  return { ip: node.ipAddress, node, loopback: false };
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

function assertPort(port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SourceError(`Port ${port} is outside the valid range 1-65535`, 422);
  }
}

/**
 * Merge `ports` and `port_range`, validate and sort them. Without either, the whole common-port
 * catalogue is audited. Mirrors PortScanRequest.resolved_ports plus NetworkScanner._normalise_ports.
 */
export function resolvePorts(request: PortScanRequest): number[] {
  const { ports, port_range: range } = request;
  if ((ports === undefined || ports === null) && (range === undefined || range === null)) {
    return [...DEFAULT_SCAN_PORTS];
  }
  const merged = new Set<number>();
  for (const port of ports ?? []) {
    assertPort(port);
    merged.add(port);
  }
  if (range !== undefined && range !== null) {
    const [start, end] = range;
    if (
      !Number.isInteger(start) ||
      !Number.isInteger(end) ||
      start < 1 ||
      end > 65535 ||
      start > end
    ) {
      throw new SourceError("port_range must satisfy 1 <= start <= end <= 65535", 422);
    }
    if (end - start + 1 > SCAN_MAX_PORTS) {
      throw new SourceError(
        `Too many ports requested (${end - start + 1}); the maximum per scan is ${SCAN_MAX_PORTS}`,
        400,
      );
    }
    for (let port = start; port <= end; port += 1) {
      merged.add(port);
    }
  }
  if (merged.size === 0) {
    throw new SourceError("At least one port must be provided", 400);
  }
  if (merged.size > SCAN_MAX_PORTS) {
    throw new SourceError(
      `Too many ports requested (${merged.size}); the maximum per scan is ${SCAN_MAX_PORTS}`,
      400,
    );
  }
  return [...merged].sort((a, b) => a - b);
}

function validateRequestOptions(request: PortScanRequest): void {
  const timeout = request.timeout_seconds;
  if (timeout !== undefined && timeout !== null && !(timeout > 0 && timeout <= MAX_TIMEOUT_SECONDS)) {
    throw new SourceError(`timeout_seconds must be greater than 0 and at most ${MAX_TIMEOUT_SECONDS}`, 422);
  }
  const concurrency = request.concurrency;
  if (
    concurrency !== undefined &&
    concurrency !== null &&
    !(Number.isInteger(concurrency) && concurrency >= 1 && concurrency <= MAX_CONCURRENCY)
  ) {
    throw new SourceError(`concurrency must be an integer between 1 and ${MAX_CONCURRENCY}`, 422);
  }
}

// ---------------------------------------------------------------------------
// Host service profiles
// ---------------------------------------------------------------------------

interface OpenService {
  port: number;
  /** What the service answers when probed (already sanitised); null when it stays silent. */
  banner: string | null;
  /** Probability that the service is present on a randomly generated device. */
  probability?: number;
}

const SSH_UBUNTU = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7";
const SSH_DEBIAN = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3";

/** Services of each simulated enterprise node (deliberately includes a few risky exposures). */
const NODE_SERVICES: Readonly<Record<string, readonly OpenService[]>> = {
  "db-primary-01": [
    { port: 22, banner: SSH_UBUNTU },
    { port: 5432, banner: null },
  ],
  "lb-edge-01": [
    { port: 22, banner: SSH_DEBIAN },
    {
      port: 80,
      banner: "HTTP/1.1 301 Moved Permanently | content-length: 0 | location: https://10.20.1.10/ | cache-control: no-cache",
    },
    { port: 443, banner: null },
    { port: 8404, banner: null },
  ],
  "ai-gpu-node-01": [
    { port: 22, banner: SSH_UBUNTU },
    { port: 8888, banner: null },
  ],
  "fw-core-01": [
    { port: 22, banner: "SSH-2.0-OpenSSH_9.5 FreeBSD-openssh-portable-9.5.p1,1" },
    { port: 23, banner: null },
    { port: 443, banner: null },
  ],
  "web-app-01": [
    { port: 22, banner: SSH_UBUNTU },
    {
      port: 80,
      banner: "HTTP/1.1 301 Moved Permanently | Server: nginx/1.24.0 (Ubuntu) | Connection: close | Location: https://10.20.2.21/",
    },
    { port: 443, banner: null },
  ],
  "cache-redis-01": [
    { port: 22, banner: SSH_UBUNTU },
    { port: 6379, banner: null },
  ],
  "nas-storage-01": [
    { port: 21, banner: "220 (vsFTPd 2.3.4)" },
    { port: 443, banner: null },
    { port: 445, banner: null },
    { port: 2049, banner: null },
  ],
  "dc-ad-01": [
    { port: 53, banner: null },
    { port: 88, banner: null },
    { port: 135, banner: null },
    { port: 389, banner: null },
    { port: 445, banner: null },
    { port: 636, banner: null },
    { port: 3389, banner: null },
    { port: 5985, banner: null },
  ],
};

interface DeviceTemplate {
  weight: number;
  services: readonly OpenService[];
}

const GENERIC_WEB_BANNER = "HTTP/1.1 200 OK | Server: nginx/1.18.0 (Ubuntu) | Content-Type: text/html";

/** Device classes for arbitrary private addresses; an empty class is a host that does not answer. */
const DEVICE_TEMPLATES: readonly DeviceTemplate[] = [
  {
    weight: 20,
    services: [
      { port: 22, banner: SSH_UBUNTU },
      { port: 80, banner: GENERIC_WEB_BANNER },
      { port: 443, banner: null, probability: 0.8 },
    ],
  },
  {
    weight: 20,
    services: [
      { port: 135, banner: null },
      { port: 139, banner: null },
      { port: 445, banner: null },
      { port: 3389, banner: null, probability: 0.4 },
      { port: 5985, banner: null, probability: 0.2 },
    ],
  },
  {
    weight: 8,
    services: [
      { port: 22, banner: "SSH-2.0-OpenSSH_7.4" },
      { port: 80, banner: "HTTP/1.1 200 OK | Server: Apache/2.2.15 (CentOS) | Content-Type: text/html" },
      { port: 443, banner: null },
      { port: 3306, banner: null, probability: 0.5 },
    ],
  },
  {
    weight: 8,
    services: [
      { port: 22, banner: SSH_DEBIAN },
      { port: 3306, banner: null, probability: 0.6 },
      { port: 5432, banner: null, probability: 0.5 },
      { port: 11211, banner: null, probability: 0.3 },
      { port: 27017, banner: null, probability: 0.3 },
    ],
  },
  {
    weight: 8,
    services: [
      { port: 80, banner: "HTTP/1.1 200 OK | Server: App-webs/ | Content-Type: text/html" },
      { port: 554, banner: null },
      { port: 8080, banner: "HTTP/1.1 200 OK | Server: App-webs/ | Content-Type: text/html", probability: 0.5 },
      { port: 1883, banner: null, probability: 0.3 },
    ],
  },
  {
    weight: 8,
    services: [
      { port: 80, banner: "HTTP/1.1 200 OK | Server: HP HTTP Server; HP LaserJet | Content-Type: text/html" },
      { port: 443, banner: null },
      { port: 515, banner: null },
      { port: 631, banner: null },
      { port: 9100, banner: null },
    ],
  },
  {
    weight: 10,
    services: [
      { port: 22, banner: SSH_UBUNTU },
      { port: 3000, banner: "HTTP/1.1 200 OK | X-Powered-By: Express | Content-Type: text/html; charset=utf-8" },
      { port: 5000, banner: "HTTP/1.1 200 OK | Server: Werkzeug/3.0.1 Python/3.11.4 | Content-Type: text/html" },
      { port: 8000, banner: "HTTP/1.0 200 OK | Server: SimpleHTTP/0.6 Python/3.11.4 | Content-Type: text/html", probability: 0.7 },
      { port: 2375, banner: "HTTP/1.1 404 Not Found | Api-Version: 1.43 | Docker/24.0.7 (linux)", probability: 0.2 },
    ],
  },
  { weight: 14, services: [] },
];

const ROUTER_SERVICES: readonly OpenService[] = [
  { port: 53, banner: null },
  { port: 80, banner: 'HTTP/1.0 401 Unauthorized | Server: Boa/0.94.14rc21 | WWW-Authenticate: Basic realm="Router"' },
  { port: 23, banner: null, probability: 0.35 },
  { port: 443, banner: null, probability: 0.5 },
  { port: 8080, banner: null, probability: 0.2 },
];

const LOOPBACK_SERVICES: readonly OpenService[] = [
  { port: 135, banner: null },
  { port: 445, banner: null },
  { port: 3000, banner: "HTTP/1.1 200 OK | X-Powered-By: Express | Content-Type: text/html; charset=utf-8", probability: 0.5 },
  { port: 5173, banner: null },
];

interface HostBehavior {
  reachable: boolean;
  services: readonly OpenService[];
  /** Typical TCP connect round-trip in milliseconds. */
  latencyMs: number;
}

function describeHost(target: ResolvedTarget, offline: boolean): HostBehavior {
  const seeded = new Random(hashString(target.ip));
  if (target.node !== undefined) {
    const services = NODE_SERVICES[target.node.hostname] ?? [];
    if (offline) {
      return { reachable: false, services: [], latencyMs: 0 };
    }
    return { reachable: true, services, latencyMs: Math.max(0.2, target.node.baseLatencyMs) };
  }
  if (target.loopback) {
    return { reachable: true, services: selectServices(LOOPBACK_SERVICES, seeded), latencyMs: 0.08 };
  }

  const lastOctet = target.ip.includes(":") ? -1 : Number(target.ip.split(".")[3]);
  let template: readonly OpenService[];
  if (lastOctet === 1 || lastOctet === 254) {
    template = ROUTER_SERVICES;
  } else {
    const total = DEVICE_TEMPLATES.reduce((sum, entry) => sum + entry.weight, 0);
    let roll = seeded.next() * total;
    template = DEVICE_TEMPLATES[DEVICE_TEMPLATES.length - 1]?.services ?? [];
    for (const entry of DEVICE_TEMPLATES) {
      roll -= entry.weight;
      if (roll < 0) {
        template = entry.services;
        break;
      }
    }
  }
  const services = selectServices(template, seeded);
  return {
    reachable: services.length > 0,
    services,
    latencyMs: Math.round(seeded.uniform(0.4, 6) * 100) / 100,
  };
}

/** Keep each optional service with its probability, using the address-seeded generator. */
function selectServices(template: readonly OpenService[], rng: Random): OpenService[] {
  return template.filter((service) => service.probability === undefined || rng.chance(service.probability));
}

// ---------------------------------------------------------------------------
// Scan outcome
// ---------------------------------------------------------------------------

export interface ScanFindingResult {
  port: number;
  service: string;
  banner: string | null;
  responseMs: number;
  riskLevel: RiskLevel;
  riskReason: string;
  recommendation: string;
}

export interface ScanOutcome {
  targetHost: string;
  resolvedIp: string;
  /** Simulated enterprise node behind the target, when the address or name belongs to one. */
  node: NodeProfile | undefined;
  startedAtMs: number;
  finishedAtMs: number;
  durationMs: number;
  hostReachable: boolean;
  hostLatencyMs: number | null;
  totalPortsScanned: number;
  findings: ScanFindingResult[];
  riskScore: number;
  overallRisk: RiskLevel;
}

export interface SimulatedScannerOptions {
  /** Multiplier applied to the simulated scan duration (0 resolves immediately; default 1). */
  delayScale?: number;
  /** Random source for latency jitter and duration jitter. */
  rng: Random;
  /** Wall clock in epoch milliseconds (injectable for tests). */
  now?: () => number;
}

export interface ScanContext {
  /** Whether the simulated node is currently offline (an injected or random outage). */
  isNodeOffline(hostname: string): boolean;
}

const ABORT_MESSAGE = "Scan aborted";

function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(new SourceError(ABORT_MESSAGE));
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new SourceError(ABORT_MESSAGE));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function median(values: readonly number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const center = sorted[middle] ?? 0;
  if (sorted.length % 2 === 1) {
    return center;
  }
  return ((sorted[middle - 1] ?? center) + center) / 2;
}

export class SimulatedScanner {
  private readonly delayScale: number;
  private readonly rng: Random;
  private readonly now: () => number;

  constructor(options: SimulatedScannerOptions) {
    this.delayScale = options.delayScale ?? 1;
    this.rng = options.rng;
    this.now = options.now ?? Date.now;
  }

  /**
   * Audit `request.target`. Validation errors reject before any delay; otherwise the promise
   * resolves after a duration proportional to the number of ports scanned, honouring `signal`.
   */
  async scan(request: PortScanRequest, context: ScanContext, signal?: AbortSignal): Promise<ScanOutcome> {
    if (signal?.aborted === true) {
      throw new SourceError(ABORT_MESSAGE);
    }
    validateRequestOptions(request);
    const ports = resolvePorts(request);
    const target = resolveTarget(request.target);
    const offline = target.node !== undefined && context.isNodeOffline(target.node.hostname);
    const host = describeHost(target, offline);

    const startedAtMs = this.now();
    const delay = this.scanDelayMs(ports.length, host.reachable);
    await sleep(delay, signal);

    const grabBanners = request.grab_banners ?? true;
    const requested = new Set(ports);
    const open = host.services.filter((service) => requested.has(service.port)).sort((a, b) => a.port - b.port);

    const findings: ScanFindingResult[] = open.map((service) => {
      const banner = grabBanners ? this.bannerFor(service) : null;
      const profile = classifyPort(service.port, banner);
      return {
        port: service.port,
        service: profile.service,
        banner,
        responseMs: this.jitter(host.latencyMs),
        riskLevel: profile.riskLevel,
        riskReason: profile.riskReason,
        recommendation: profile.recommendation,
      };
    });

    // Like the backend: median of three TCP round-trips, falling back to an ICMP echo when no port
    // was open. An unreachable host has neither.
    const hostLatencyMs = host.reachable
      ? Math.round(median([this.jitter(host.latencyMs), this.jitter(host.latencyMs), this.jitter(host.latencyMs)]) * 100) / 100
      : null;

    const levels = findings.map((finding) => finding.riskLevel);
    const finishedAtMs = this.now();
    return {
      targetHost: request.target.trim(),
      resolvedIp: target.ip,
      node: target.node,
      startedAtMs,
      finishedAtMs,
      durationMs: Math.max(1, finishedAtMs - startedAtMs),
      hostReachable: host.reachable,
      hostLatencyMs,
      totalPortsScanned: ports.length,
      findings,
      riskScore: calculateRiskScore(levels),
      overallRisk: highestRisk(levels),
    };
  }

  /** Plain-HTTP ports answer a HEAD probe, other services only when they greet first; TLS ports stay mute. */
  private bannerFor(service: OpenService): string | null {
    if (TLS_PORTS.has(service.port)) {
      return null;
    }
    if (service.banner === null) {
      return null;
    }
    const isHttp = service.banner.startsWith("HTTP/");
    if (isHttp && !HTTP_PORTS.has(service.port)) {
      return null;
    }
    return service.banner;
  }

  private jitter(latencyMs: number): number {
    return Math.round(Math.max(0.05, latencyMs * this.rng.uniform(0.8, 1.4)) * 100) / 100;
  }

  private scanDelayMs(portCount: number, reachable: boolean): number {
    if (this.delayScale <= 0) {
      return 0;
    }
    let delay = MIN_SCAN_DELAY_MS + (Math.min(portCount, SCAN_MAX_PORTS) / SCAN_MAX_PORTS) * 2000;
    if (!reachable) {
      delay += UNREACHABLE_EXTRA_DELAY_MS;
    }
    delay *= this.rng.uniform(0.92, 1.08);
    return Math.min(MAX_SCAN_DELAY_MS, Math.max(MIN_SCAN_DELAY_MS, delay)) * this.delayScale;
  }
}

/** Hostnames the simulated scanner can resolve, for UI hints and tests. */
export const SCANNABLE_HOSTNAMES: readonly string[] = NODE_PROFILES.map((profile) => profile.hostname);
