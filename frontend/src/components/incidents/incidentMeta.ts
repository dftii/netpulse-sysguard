import { Cpu, HardDrive, MemoryStick, Network, ServerCrash, Thermometer, Timer, type LucideIcon } from "lucide-react";
import type { AnomalyType } from "../../types/api";

/** One icon per anomaly type. */
export const ANOMALY_ICONS: Record<AnomalyType, LucideIcon> = {
  cpu_spike: Cpu,
  memory_leak: MemoryStick,
  bandwidth_saturation: Network,
  critical_latency: Timer,
  disk_pressure: HardDrive,
  service_down: ServerCrash,
  thermal_spike: Thermometer,
};

/** "just now", "12s ago", "4m ago", "3h ago", "2d ago". */
export function formatRelativeTime(iso: string, nowMs: number): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "unknown";
  const seconds = Math.max(0, Math.round((nowMs - then) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/** Compact number formatting for observed values and thresholds. */
export function formatMetricValue(value: number): string {
  const abs = Math.abs(value);
  if (abs >= 1000) return value.toFixed(0);
  if (abs >= 100) return value.toFixed(1);
  return value.toFixed(2);
}

/** Human readable message of a failed operation. */
export function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message !== "") return error.message;
  return fallback;
}
