/**
 * Owns the active TelemetrySource and turns its frames into the dashboard state.
 *
 * Lifecycle: on mount the initial mode is resolved (backend probe or static hosting), a source is
 * created and started, and every frame becomes exactly one reducer dispatch. The effect cleanup
 * stops the source and invalidates in-flight async work through a generation counter, so React
 * StrictMode's mount/unmount/mount cycle never leaves two sources, sockets or timers alive.
 */

import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { ANOMALY_LABELS } from "../lib/format";
import { BackendSource } from "../services/backendSource";
import {
  getApiBaseUrl,
  isMixedContentBackend,
  persistMode,
  probeBackend,
  resolveInitialMode,
} from "../services/modeResolver";
import { SimulationSource } from "../services/simulation/simulationSource";
import type { TelemetrySource, Unsubscribe } from "../services/telemetrySource";
import { SourceError } from "../services/telemetrySource";
import type {
  IncidentInjectionRequest,
  PortAuditRead,
  PortAuditSummary,
  PortScanRequest,
} from "../types/api";
import type {
  ConnectionMode,
  LogLevel,
  LogSource,
  SourcePhase,
  TelemetryController,
} from "../types/dashboard";
import { scanCompletionLogs, scanFailureLog, scanStartLog } from "./scanLogs";
import { createInitialState, telemetryReducer, type LogDraft } from "./telemetryReducer";

/** Number of historical alerts requested when a source starts (or recovers from a dropped link). */
const INITIAL_ALERT_LIMIT = 50;

interface ConnectionMeta {
  mode: ConnectionMode;
  resolving: boolean;
  backendAvailable: boolean | null;
  autoSelected: boolean;
}

interface ActiveSession {
  source: TelemetrySource;
  unsubscribe: () => void;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function useTelemetry(): TelemetryController {
  const [reducerState, dispatch] = useReducer(telemetryReducer, undefined, createInitialState);
  const [meta, setMeta] = useState<ConnectionMeta>({
    mode: "simulation",
    resolving: true,
    backendAvailable: null,
    autoSelected: false,
  });

  const sessionRef = useRef<ActiveSession | null>(null);
  const modeRef = useRef<ConnectionMode | null>(null);
  /** Bumped whenever a newer start/switch (or the unmount) supersedes in-flight async work. */
  const generationRef = useRef(0);

  const writeLogs = useCallback((drafts: LogDraft[]) => {
    dispatch({ type: "log", drafts, now: Date.now() });
  }, []);

  const log = useCallback(
    (level: LogLevel, source: LogSource, message: string, host: string | null = null) => {
      writeLogs([{ level, source, host, message }]);
    },
    [writeLogs],
  );

  const clearLogs = useCallback(() => {
    dispatch({ type: "clearLogs" });
  }, []);

  const stopCurrent = useCallback(() => {
    const session = sessionRef.current;
    sessionRef.current = null;
    modeRef.current = null;
    if (session === null) return;
    session.unsubscribe();
    session.source.stop();
  }, []);

  const loadAlerts = useCallback(
    (source: TelemetrySource) => {
      source
        .listAlerts({ limit: INITIAL_ALERT_LIMIT })
        .then((page) => {
          if (sessionRef.current?.source !== source) return;
          dispatch({ type: "alertsLoaded", alerts: page.items });
        })
        .catch((error: unknown) => {
          if (sessionRef.current?.source !== source) return;
          log("warn", "system", `Could not load alert history: ${errorMessage(error)}`);
        });
    },
    [log],
  );

  /** Replaces the active source: tears down the old one, resets histories (not logs) and starts the new one. */
  const startSource = useCallback(
    (mode: ConnectionMode) => {
      stopCurrent();
      dispatch({ type: "reset", mode });

      const source: TelemetrySource = mode === "backend" ? new BackendSource(getApiBaseUrl()) : new SimulationSource();
      let previousPhase: SourcePhase = "stopped";

      const offFrame: Unsubscribe = source.onFrame((frame) => {
        dispatch({ type: "frame", frame, status: source.getStatus(), now: Date.now() });
      });
      const offStatus: Unsubscribe = source.onStatus((status) => {
        dispatch({ type: "status", status, now: Date.now() });
        const recovered = status.phase === "live" && (previousPhase === "reconnecting" || previousPhase === "error");
        previousPhase = status.phase;
        // Alerts raised while the link was down never arrive as frames: pull them again.
        if (recovered) loadAlerts(source);
      });

      sessionRef.current = {
        source,
        unsubscribe: () => {
          offFrame();
          offStatus();
        },
      };
      modeRef.current = mode;
      setMeta((current) => ({ ...current, mode, resolving: false }));

      source.start();
      dispatch({ type: "status", status: source.getStatus(), now: Date.now() });
      loadAlerts(source);
    },
    [stopCurrent, loadAlerts],
  );

  // Initial resolution and cleanup.
  useEffect(() => {
    const generation = ++generationRef.current;

    void resolveInitialMode().then((resolved) => {
      if (generation !== generationRef.current) return;
      const baseUrl = getApiBaseUrl();
      if (resolved.mode === "backend") {
        log("info", "system", `Backend reachable at ${baseUrl}; using live telemetry`);
      } else if (resolved.backendAvailable === false) {
        log("warn", "system", `Backend not reachable at ${baseUrl}; running the in-browser simulation`);
      } else if (resolved.autoSelected) {
        log("info", "system", "Static hosting detected; running the in-browser simulation");
      } else {
        log("info", "system", "Running the in-browser simulation");
      }
      setMeta((current) => ({
        ...current,
        mode: resolved.mode,
        backendAvailable: resolved.backendAvailable,
        autoSelected: resolved.autoSelected,
      }));
      startSource(resolved.mode);
    });

    return () => {
      generationRef.current += 1;
      stopCurrent();
    };
  }, [log, startSource, stopCurrent]);

  const setMode = useCallback(
    (target: ConnectionMode) => {
      const activeSource = sessionRef.current?.source ?? null;
      if (modeRef.current === target && activeSource !== null) {
        const phase = activeSource.getStatus().phase;
        // Re-selecting the current mode only matters as a retry of a backend that is not streaming.
        if (target === "simulation" || phase === "live" || phase === "connecting") return;
      }

      const generation = ++generationRef.current;
      log("info", "operator", `Switching to ${target} mode`);

      const apply = (): void => {
        startSource(target);
        setMeta((current) => ({
          ...current,
          autoSelected: false,
          backendAvailable: target === "backend" ? true : current.backendAvailable,
        }));
        persistMode(target);
      };

      if (target === "simulation") {
        apply();
        return;
      }

      const baseUrl = getApiBaseUrl();
      if (isMixedContentBackend(baseUrl)) {
        // An https page (e.g. GitHub Pages) cannot reach a plain-http backend: skip the doomed request.
        setMeta((current) => ({ ...current, backendAvailable: false }));
        log(
          "error",
          "system",
          `Cannot reach ${baseUrl} from an https page (mixed content); run the dashboard locally to use the live backend`,
        );
        if (sessionRef.current === null) startSource("simulation");
        return;
      }
      void probeBackend(baseUrl).then((reachable) => {
        if (generation !== generationRef.current) return;
        setMeta((current) => ({ ...current, backendAvailable: reachable }));
        if (reachable) {
          log("info", "system", `Backend reachable at ${baseUrl}`);
          apply();
          return;
        }
        if (sessionRef.current === null) {
          log("error", "system", `Backend unreachable at ${baseUrl}; falling back to the in-browser simulation`);
          startSource("simulation");
          setMeta((current) => ({ ...current, autoSelected: true }));
        } else {
          log("error", "system", `Backend unreachable at ${baseUrl}; staying in ${modeRef.current ?? "simulation"} mode`);
        }
      });
    },
    [log, startSource],
  );

  const requireSource = useCallback((): TelemetrySource => {
    const source = sessionRef.current?.source;
    if (!source) throw new SourceError("No active telemetry source yet");
    return source;
  }, []);

  const acknowledgeAlert = useCallback(
    async (alertId: number): Promise<void> => {
      const source = requireSource();
      try {
        const updated = await source.acknowledgeAlert(alertId);
        dispatch({ type: "alertUpdated", alert: updated });
        log("info", "operator", `Acknowledged alert #${alertId}`, updated.node_hostname);
      } catch (error) {
        log("error", "operator", `Could not acknowledge alert #${alertId}: ${errorMessage(error)}`);
        throw error;
      }
    },
    [requireSource, log],
  );

  const injectIncident = useCallback(
    async (request: IncidentInjectionRequest): Promise<void> => {
      const source = requireSource();
      const label = ANOMALY_LABELS[request.anomaly_type];
      log("info", "operator", `Injecting "${label}" on ${request.hostname} for ${request.duration_seconds} s`, request.hostname);
      try {
        const response = await source.injectIncident(request);
        if (response.accepted) {
          log("info", "operator", `Incident accepted on ${response.hostname}: ${label}`, response.hostname);
        } else {
          log("warn", "operator", `Incident on ${response.hostname} was not accepted`, response.hostname);
        }
      } catch (error) {
        log("error", "operator", `Incident injection failed: ${errorMessage(error)}`, request.hostname);
        throw error;
      }
    },
    [requireSource, log],
  );

  const runPortScan = useCallback(
    async (request: PortScanRequest, signal?: AbortSignal): Promise<PortAuditRead> => {
      const source = requireSource();
      writeLogs([scanStartLog(request)]);
      try {
        const audit = await source.runPortScan(request, signal);
        writeLogs(scanCompletionLogs(audit));
        return audit;
      } catch (error) {
        writeLogs([scanFailureLog(request, errorMessage(error), signal?.aborted === true)]);
        throw error;
      }
    },
    [requireSource, writeLogs],
  );

  const listPortScans = useCallback(
    async (limit?: number): Promise<PortAuditSummary[]> => {
      const source = requireSource();
      try {
        return await source.listPortScans(limit);
      } catch (error) {
        log("error", "scanner", `Could not list port audits: ${errorMessage(error)}`);
        throw error;
      }
    },
    [requireSource, log],
  );

  return useMemo<TelemetryController>(
    () => ({
      state: reducerState.view,
      mode: meta.mode,
      resolving: meta.resolving,
      backendAvailable: meta.backendAvailable,
      autoSelected: meta.autoSelected,
      setMode,
      acknowledgeAlert,
      injectIncident,
      runPortScan,
      listPortScans,
      log,
      clearLogs,
    }),
    [reducerState.view, meta, setMode, acknowledgeAlert, injectIncident, runPortScan, listPortScans, log, clearLogs],
  );
}
