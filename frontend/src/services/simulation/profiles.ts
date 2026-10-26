/**
 * Static specification and behavioural baseline of the eight simulated enterprise nodes.
 * Values are a faithful port of backend/app/services/telemetry_collector.py (_PROFILES); node ids
 * follow the declaration order (1..8).
 */

import type { NodeRead, NodeRole, NodeStatus } from "../../types/api";

export interface NodeProfile {
  id: number;
  hostname: string;
  displayName: string;
  role: NodeRole;
  ipAddress: string;
  osName: string;
  location: string;
  cpuCores: number;
  memoryTotalMb: number;
  diskTotalGb: number;
  linkCapacityMbps: number;
  baseCpu: number;
  cpuDiurnal: number;
  cpuSigma: number;
  baseMemory: number;
  baseDisk: number;
  diskGrowthPerSecond: number;
  baseUploadFraction: number;
  baseDownloadFraction: number;
  netDiurnal: number;
  baseLatencyMs: number;
  baseProcesses: number;
  processCpuFactor: number;
  tempIdleC: number;
  tempLoadC: number;
  burstProbability: number;
  burstMagnitude: number;
}

export const NODE_PROFILES: readonly NodeProfile[] = [
  {
    id: 1,
    hostname: "db-primary-01",
    displayName: "PostgreSQL Primary",
    role: "database",
    ipAddress: "10.20.4.11",
    osName: "Ubuntu 22.04.4 LTS (PostgreSQL 16.2)",
    location: "DC Madrid - Rack A3",
    cpuCores: 16,
    memoryTotalMb: 65536,
    diskTotalGb: 2000,
    linkCapacityMbps: 10000,
    baseCpu: 38,
    cpuDiurnal: 14,
    cpuSigma: 1.8,
    baseMemory: 68,
    baseDisk: 52,
    diskGrowthPerSecond: 0.00005,
    baseUploadFraction: 0.02,
    baseDownloadFraction: 0.03,
    netDiurnal: 0.35,
    baseLatencyMs: 1.2,
    baseProcesses: 310,
    processCpuFactor: 0.6,
    tempIdleC: 40,
    tempLoadC: 28,
    burstProbability: 0.01,
    burstMagnitude: 18,
  },
  {
    id: 2,
    hostname: "lb-edge-01",
    displayName: "HAProxy Edge Balancer",
    role: "load_balancer",
    ipAddress: "10.20.1.10",
    osName: "Debian 12 (HAProxy 2.8)",
    location: "DC Madrid - Rack A1",
    cpuCores: 8,
    memoryTotalMb: 16384,
    diskTotalGb: 240,
    linkCapacityMbps: 10000,
    baseCpu: 24,
    cpuDiurnal: 10,
    cpuSigma: 1.4,
    baseMemory: 36,
    baseDisk: 28,
    diskGrowthPerSecond: 0.00001,
    baseUploadFraction: 0.06,
    baseDownloadFraction: 0.06,
    netDiurnal: 0.4,
    baseLatencyMs: 0.4,
    baseProcesses: 140,
    processCpuFactor: 0.3,
    tempIdleC: 38,
    tempLoadC: 24,
    burstProbability: 0.012,
    burstMagnitude: 14,
  },
  {
    id: 3,
    hostname: "ai-gpu-node-01",
    displayName: "AI GPU Compute Node",
    role: "ai_compute",
    ipAddress: "10.20.3.40",
    osName: "Ubuntu 22.04.4 LTS (CUDA 12.4)",
    location: "DC Madrid - Rack B2",
    cpuCores: 64,
    memoryTotalMb: 262144,
    diskTotalGb: 7680,
    linkCapacityMbps: 10000,
    baseCpu: 58,
    cpuDiurnal: 8,
    cpuSigma: 2.4,
    baseMemory: 72,
    baseDisk: 45,
    diskGrowthPerSecond: 0.00004,
    baseUploadFraction: 0.03,
    baseDownloadFraction: 0.08,
    netDiurnal: 0.3,
    baseLatencyMs: 2.5,
    baseProcesses: 420,
    processCpuFactor: 0.9,
    tempIdleC: 52,
    tempLoadC: 32,
    burstProbability: 0.02,
    burstMagnitude: 20,
  },
  {
    id: 4,
    hostname: "fw-core-01",
    displayName: "pfSense Core Firewall",
    role: "firewall",
    ipAddress: "10.20.0.1",
    osName: "pfSense 2.7.2 (FreeBSD 14.0)",
    location: "DC Madrid - Rack A1",
    cpuCores: 8,
    memoryTotalMb: 32768,
    diskTotalGb: 480,
    linkCapacityMbps: 10000,
    baseCpu: 30,
    cpuDiurnal: 12,
    cpuSigma: 1.6,
    baseMemory: 42,
    baseDisk: 22,
    diskGrowthPerSecond: 0.00002,
    baseUploadFraction: 0.22,
    baseDownloadFraction: 0.24,
    netDiurnal: 0.4,
    baseLatencyMs: 0.3,
    baseProcesses: 95,
    processCpuFactor: 0.2,
    tempIdleC: 39,
    tempLoadC: 26,
    burstProbability: 0.012,
    burstMagnitude: 16,
  },
  {
    id: 5,
    hostname: "web-app-01",
    displayName: "Nginx Web Server",
    role: "web_server",
    ipAddress: "10.20.2.21",
    osName: "Ubuntu 22.04.4 LTS (nginx 1.24)",
    location: "DC Madrid - Rack A4",
    cpuCores: 8,
    memoryTotalMb: 16384,
    diskTotalGb: 500,
    linkCapacityMbps: 1000,
    baseCpu: 33,
    cpuDiurnal: 15,
    cpuSigma: 1.7,
    baseMemory: 52,
    baseDisk: 41,
    diskGrowthPerSecond: 0.00003,
    baseUploadFraction: 0.18,
    baseDownloadFraction: 0.06,
    netDiurnal: 0.45,
    baseLatencyMs: 1.5,
    baseProcesses: 180,
    processCpuFactor: 0.7,
    tempIdleC: 37,
    tempLoadC: 25,
    burstProbability: 0.015,
    burstMagnitude: 16,
  },
  {
    id: 6,
    hostname: "cache-redis-01",
    displayName: "Redis Cache",
    role: "cache",
    ipAddress: "10.20.4.31",
    osName: "Ubuntu 22.04.4 LTS (Redis 7.2)",
    location: "DC Madrid - Rack A3",
    cpuCores: 8,
    memoryTotalMb: 131072,
    diskTotalGb: 480,
    linkCapacityMbps: 10000,
    baseCpu: 22,
    cpuDiurnal: 9,
    cpuSigma: 1.2,
    baseMemory: 71,
    baseDisk: 18,
    diskGrowthPerSecond: 0.00001,
    baseUploadFraction: 0.05,
    baseDownloadFraction: 0.05,
    netDiurnal: 0.35,
    baseLatencyMs: 0.4,
    baseProcesses: 90,
    processCpuFactor: 0.2,
    tempIdleC: 37,
    tempLoadC: 22,
    burstProbability: 0.01,
    burstMagnitude: 12,
  },
  {
    id: 7,
    hostname: "nas-storage-01",
    displayName: "TrueNAS Storage",
    role: "storage",
    ipAddress: "10.20.5.50",
    osName: "TrueNAS SCALE 24.04 (Debian 12)",
    location: "DC Madrid - Rack C1",
    cpuCores: 12,
    memoryTotalMb: 65536,
    diskTotalGb: 96000,
    linkCapacityMbps: 10000,
    baseCpu: 18,
    cpuDiurnal: 7,
    cpuSigma: 1.1,
    baseMemory: 63,
    baseDisk: 74,
    diskGrowthPerSecond: 0.00008,
    baseUploadFraction: 0.1,
    baseDownloadFraction: 0.08,
    netDiurnal: 0.3,
    baseLatencyMs: 4,
    baseProcesses: 240,
    processCpuFactor: 0.4,
    tempIdleC: 41,
    tempLoadC: 20,
    burstProbability: 0.01,
    burstMagnitude: 14,
  },
  {
    id: 8,
    hostname: "dc-ad-01",
    displayName: "Active Directory DC",
    role: "domain_controller",
    ipAddress: "10.20.6.5",
    osName: "Windows Server 2022 Datacenter 21H2",
    location: "DC Madrid - Rack B1",
    cpuCores: 4,
    memoryTotalMb: 16384,
    diskTotalGb: 256,
    linkCapacityMbps: 1000,
    baseCpu: 14,
    cpuDiurnal: 6,
    cpuSigma: 1,
    baseMemory: 58,
    baseDisk: 44,
    diskGrowthPerSecond: 0.00002,
    baseUploadFraction: 0.02,
    baseDownloadFraction: 0.02,
    netDiurnal: 0.3,
    baseLatencyMs: 1,
    baseProcesses: 120,
    processCpuFactor: 0.3,
    tempIdleC: 36,
    tempLoadC: 20,
    burstProbability: 0.008,
    burstMagnitude: 10,
  },
];

const PROFILE_BY_HOSTNAME: ReadonlyMap<string, NodeProfile> = new Map(
  NODE_PROFILES.map((profile) => [profile.hostname, profile]),
);
const PROFILE_BY_ID: ReadonlyMap<number, NodeProfile> = new Map(
  NODE_PROFILES.map((profile) => [profile.id, profile]),
);
const PROFILE_BY_IP: ReadonlyMap<string, NodeProfile> = new Map(
  NODE_PROFILES.map((profile) => [profile.ipAddress, profile]),
);

export function profileByHostname(hostname: string): NodeProfile | undefined {
  return PROFILE_BY_HOSTNAME.get(hostname);
}

export function profileById(id: number): NodeProfile | undefined {
  return PROFILE_BY_ID.get(id);
}

export function profileByIp(ipAddress: string): NodeProfile | undefined {
  return PROFILE_BY_IP.get(ipAddress);
}

/** Link capacity expressed in kbps (the unit of the network metrics). */
export function linkCapacityKbps(profile: NodeProfile): number {
  return profile.linkCapacityMbps * 1000;
}

/** Build the REST representation of a node with its live status. */
export function toNodeRead(
  profile: NodeProfile,
  status: NodeStatus,
  createdAt: string,
  lastSeenAt: string | null,
): NodeRead {
  return {
    id: profile.id,
    hostname: profile.hostname,
    display_name: profile.displayName,
    role: profile.role,
    ip_address: profile.ipAddress,
    os_name: profile.osName,
    location: profile.location,
    is_simulated: true,
    cpu_cores: profile.cpuCores,
    memory_total_mb: profile.memoryTotalMb,
    disk_total_gb: profile.diskTotalGb,
    link_capacity_mbps: profile.linkCapacityMbps,
    status,
    created_at: createdAt,
    last_seen_at: lastSeenAt,
  };
}
