/**
 * Typed fetch wrapper for the FastAPI backend.
 * Handles base-URL normalisation, JSON encoding, per-request timeouts, caller cancellation and the
 * mapping of every failure (network, timeout, HTTP error, FastAPI `detail`) to a SourceError.
 */

import type { AlertQuery } from "../types/api";
import { SourceError } from "./telemetrySource";

export const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
export const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

export type QueryValue = string | number | boolean | null | undefined;
export type QueryParams = Record<string, QueryValue>;

export interface RequestOptions {
  query?: QueryParams;
  /** JSON-serialisable request body. */
  body?: unknown;
  /** Abort the request after this many milliseconds (default 10 s). */
  timeoutMs?: number;
  /** Caller-owned cancellation signal, combined with the timeout. */
  signal?: AbortSignal;
}

/** Trims whitespace and trailing slashes; falls back to the default backend origin when empty. */
export function normalizeBaseUrl(raw: string | null | undefined): string {
  const trimmed = (raw ?? "").trim().replace(/\/+$/, "");
  return trimmed === "" ? DEFAULT_API_BASE_URL : trimmed;
}

/** Backend origin configured through VITE_API_BASE_URL (normalised). */
export function resolveApiBaseUrl(): string {
  return normalizeBaseUrl(import.meta.env.VITE_API_BASE_URL);
}

/**
 * Derives the WebSocket endpoint from the REST base URL:
 * http -> ws, https -> wss, any path prefix on the base URL is preserved.
 */
export function toWebSocketUrl(baseUrl: string, path = "/ws/telemetry"): string {
  const reference = typeof location === "undefined" ? undefined : location.href;
  const url = new URL(normalizeBaseUrl(baseUrl), reference);
  if (url.protocol === "http:") url.protocol = "ws:";
  else if (url.protocol === "https:") url.protocol = "wss:";
  url.pathname = `${url.pathname.replace(/\/+$/, "")}${path}`;
  url.search = "";
  url.hash = "";
  return url.toString();
}

/** Serialises query parameters, skipping null/undefined values. Returns "" or "?a=1&b=2". */
export function buildQueryString(params: QueryParams | undefined): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined) continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text === "" ? "" : `?${text}`;
}

/** Query parameters for GET /api/alerts. */
export function alertQueryParams(query: AlertQuery | undefined): QueryParams {
  if (!query) return {};
  return {
    node_id: query.node_id,
    severity: query.severity,
    anomaly_type: query.anomaly_type,
    acknowledged: query.acknowledged,
    limit: query.limit,
    offset: query.offset,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Turns FastAPI's `detail` (string, validation-error array or object) into one readable line. */
function formatDetail(detail: unknown): string | null {
  if (typeof detail === "string") return detail.trim() === "" ? null : detail;
  if (Array.isArray(detail)) {
    const parts = detail
      .map((item) => {
        if (typeof item === "string") return item;
        if (!isRecord(item)) return null;
        const message = typeof item.msg === "string" ? item.msg : null;
        if (message === null) return null;
        const field = Array.isArray(item.loc)
          ? item.loc.filter((part) => part !== "body" && part !== "query").join(".")
          : "";
        return field === "" ? message : `${field}: ${message}`;
      })
      .filter((part): part is string => part !== null);
    return parts.length > 0 ? parts.join("; ") : null;
  }
  if (isRecord(detail)) {
    if (typeof detail.message === "string") return detail.message;
    return JSON.stringify(detail);
  }
  return null;
}

function extractErrorMessage(text: string, status: number, statusText: string): string {
  if (text.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(text);
      if (isRecord(parsed)) {
        const detail = formatDetail(parsed.detail);
        if (detail !== null) return detail;
      }
    } catch {
      // Not JSON (for example a proxy error page): fall through to the generic message.
    }
  }
  return statusText.trim() === "" ? `HTTP ${status}` : `HTTP ${status} ${statusText}`;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class ApiClient {
  readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
  }

  get<T>(path: string, options: Omit<RequestOptions, "body"> = {}): Promise<T> {
    return this.request<T>("GET", path, options);
  }

  post<T>(path: string, body: unknown, options: Omit<RequestOptions, "body"> = {}): Promise<T> {
    return this.request<T>("POST", path, { ...options, body });
  }

  patch<T>(path: string, body?: unknown, options: Omit<RequestOptions, "body"> = {}): Promise<T> {
    return this.request<T>("PATCH", path, { ...options, body });
  }

  async request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
    const { query, body, signal, timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS } = options;
    const url = `${this.baseUrl}${path}${buildQueryString(query)}`;

    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";

    let response: Response;
    let text: string;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: combined,
      });
      text = await response.text();
    } catch (error) {
      if (signal?.aborted) throw new SourceError("Request cancelled");
      if (timeoutSignal.aborted) {
        throw new SourceError(`${method} ${path} timed out after ${Math.round(timeoutMs / 1000)} s`);
      }
      throw new SourceError(`Cannot reach the backend at ${this.baseUrl}: ${errorText(error)}`);
    }

    if (!response.ok) {
      throw new SourceError(extractErrorMessage(text, response.status, response.statusText), response.status);
    }
    if (response.status === 204 || text.trim() === "") return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new SourceError(`${method} ${path} returned invalid JSON`, response.status);
    }
  }
}
