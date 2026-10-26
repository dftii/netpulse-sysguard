/** Formatting helpers shared by the dashboard components. */

import type { AnomalyType, NodeRole } from "../types/api";

export function kbpsToMbps(kbps: number): number {
  return kbps / 1000;
}

/** "842 kbps", "12.4 Mbps", "1.20 Gbps". */
export function formatBandwidth(kbps: number): string {
  if (kbps < 1000) return `${kbps.toFixed(0)} kbps`;
  const mbps = kbps / 1000;
  if (mbps < 1000) return `${mbps.toFixed(mbps < 100 ? 1 : 0)} Mbps`;
  return `${(mbps / 1000).toFixed(2)} Gbps`;
}

export function formatPercent(value: number, digits = 1): string {
  return `${value.toFixed(digits)}%`;
}

export function formatLatency(ms: number | null): string {
  if (ms === null) return "—";
  return ms < 10 ? `${ms.toFixed(2)} ms` : `${ms.toFixed(0)} ms`;
}

export function formatTemperature(celsius: number | null): string {
  return celsius === null ? "—" : `${celsius.toFixed(1)} °C`;
}

/** "45s", "12m 03s", "3h 07m", "41d 06h". */
export function formatUptime(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const days = Math.floor(s / 86_400);
  const hours = Math.floor((s % 86_400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const secs = s % 60;
  const pad = (n: number) => n.toString().padStart(2, "0");
  if (days > 0) return `${days}d ${pad(hours)}h`;
  if (hours > 0) return `${hours}h ${pad(minutes)}m`;
  if (minutes > 0) return `${minutes}m ${pad(secs)}s`;
  return `${secs}s`;
}

/** "14:03:27" in the viewer's local time. */
export function formatClock(epochMs: number): string {
  return new Date(epochMs).toLocaleTimeString("en-GB", { hour12: false });
}

/** "2026-10-26 14:03:27" in the viewer's local time. */
export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  const day = date.toLocaleDateString("en-CA");
  return `${day} ${date.toLocaleTimeString("en-GB", { hour12: false })}`;
}

export function formatBytesMb(mb: number): string {
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb.toFixed(0)} MB`;
}

export const ANOMALY_LABELS: Record<AnomalyType, string> = {
  cpu_spike: "CPU spike",
  memory_leak: "Memory leak",
  bandwidth_saturation: "Bandwidth saturation",
  critical_latency: "Critical latency",
  disk_pressure: "Disk pressure",
  service_down: "Service down",
  thermal_spike: "Thermal spike",
};

export const ROLE_LABELS: Record<NodeRole, string> = {
  host: "Host",
  database: "Database",
  load_balancer: "Load balancer",
  ai_compute: "AI compute",
  firewall: "Firewall",
  web_server: "Web server",
  cache: "Cache",
  storage: "Storage",
  domain_controller: "Domain controller",
};
