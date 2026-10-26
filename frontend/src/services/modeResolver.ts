/**
 * Decides where telemetry comes from at startup: the FastAPI backend when it is reachable, or the
 * in-browser simulation engine (always on static hosting such as GitHub Pages).
 */

import type { HealthResponse } from "../types/api";
import type { ConnectionMode } from "../types/dashboard";
import { ApiClient, resolveApiBaseUrl } from "./apiClient";

export const MODE_STORAGE_KEY = "netpulse.mode";
export const DEFAULT_PROBE_TIMEOUT_MS = 1_500;

export interface ResolvedMode {
  mode: ConnectionMode;
  /** True when the backend answered the probe, false when it did not, null when no probe was made. */
  backendAvailable: boolean | null;
  /** True when the mode was picked automatically rather than by the user or by VITE_DEFAULT_MODE. */
  autoSelected: boolean;
}

/** Backend origin configured at build time (VITE_API_BASE_URL), normalised. */
export function getApiBaseUrl(): string {
  return resolveApiBaseUrl();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** True when GET {baseUrl}/api/health answers 200 with a JSON body that carries a `status` field. */
export async function probeBackend(baseUrl: string, timeoutMs: number = DEFAULT_PROBE_TIMEOUT_MS): Promise<boolean> {
  try {
    const body = await new ApiClient(baseUrl).get<HealthResponse | null>("/api/health", { timeoutMs });
    return isRecord(body) && typeof body.status === "string";
  } catch {
    return false;
  }
}

/** True on GitHub Pages hosting, or when the build forces the simulation (no backend can exist there). */
export function isStaticHosting(): boolean {
  if (import.meta.env.VITE_DEFAULT_MODE === "simulation") return true;
  if (typeof window === "undefined") return false;
  return window.location.hostname.toLowerCase().endsWith(".github.io");
}

/** The mode the user picked manually in a previous session, if any. */
export function loadStoredMode(): ConnectionMode | null {
  try {
    const value = window.localStorage.getItem(MODE_STORAGE_KEY);
    return value === "backend" || value === "simulation" ? value : null;
  } catch {
    return null;
  }
}

/** Remembers the user's manual mode choice for the next load. */
export function persistMode(mode: ConnectionMode): void {
  try {
    window.localStorage.setItem(MODE_STORAGE_KEY, mode);
  } catch {
    // Storage can be unavailable (private mode, blocked site data); the choice is simply not remembered.
  }
}

/**
 * Resolution order:
 *  1. VITE_DEFAULT_MODE "backend" / "simulation" forces that mode.
 *  2. Static hosting goes straight to the simulation without probing.
 *  3. A stored manual "simulation" choice is honoured without probing.
 *  4. Otherwise the backend is probed: reachable -> backend, unreachable -> simulation (auto-selected).
 *     A stored "backend" choice is honoured only when the probe succeeds.
 */
export async function resolveInitialMode(): Promise<ResolvedMode> {
  const forced = import.meta.env.VITE_DEFAULT_MODE;
  if (forced === "backend" || forced === "simulation") {
    return { mode: forced, backendAvailable: null, autoSelected: false };
  }

  if (isStaticHosting()) {
    return { mode: "simulation", backendAvailable: null, autoSelected: true };
  }

  const stored = loadStoredMode();
  if (stored === "simulation") {
    return { mode: "simulation", backendAvailable: null, autoSelected: false };
  }

  const reachable = await probeBackend(getApiBaseUrl());
  if (reachable) {
    return { mode: "backend", backendAvailable: true, autoSelected: false };
  }
  return { mode: "simulation", backendAvailable: false, autoSelected: true };
}
