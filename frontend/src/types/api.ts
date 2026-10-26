/**
 * TypeScript mirror of the backend contracts (backend/app/enums.py and backend/app/schemas.py).
 * Every timestamp is an ISO-8601 string with a UTC offset, exactly as the API serialises it.
 */

export const NODE_ROLES = [
  "host",
  "database",
  "load_balancer",
  "ai_compute",
  "firewall",
  "web_server",
  "cache",
  "storage",
  "domain_controller",
] as const;
export type NodeRole = (typeof NODE_ROLES)[number];

export const NODE_STATUSES = ["online", "warning", "critical", "offline"] as const;
export type NodeStatus = (typeof NODE_STATUSES)[number];

export const RISK_LEVELS = ["info", "low", "medium", "high", "critical"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const PORT_STATES = ["open", "closed", "filtered"] as const;
export type PortState = (typeof PORT_STATES)[number];

export const ANOMALY_TYPES = [
  "cpu_spike",
  "memory_leak",
  "bandwidth_saturation",
  "critical_latency",
  "disk_pressure",
  "service_down",
  "thermal_spike",
] as const;
export type AnomalyType = (typeof ANOMALY_TYPES)[number];

export const ALERT_SEVERITIES = ["info", "warning", "critical"] as const;
export type AlertSeverity = (typeof ALERT_SEVERITIES)[number];

// ---------------------------------------------------------------------------
// Nodes and telemetry
// ---------------------------------------------------------------------------

export interface NodeRead {
  id: number;
  hostname: string;
  display_name: string;
  role: NodeRole;
  ip_address: string;
  os_name: string;
  location: string;
  is_simulated: boolean;
  cpu_cores: number;
  memory_total_mb: number;
  disk_total_gb: number;
  link_capacity_mbps: number;
  status: NodeStatus;
  created_at: string;
  last_seen_at: string | null;
}

export interface MetricValues {
  cpu_percent: number;
  memory_percent: number;
  memory_used_mb: number;
  disk_percent: number;
  latency_ms: number | null;
  net_upload_kbps: number;
  net_download_kbps: number;
  process_count: number;
  temperature_c: number | null;
}

/** Live snapshot of one node, streamed once per tick. */
export interface NodeTelemetry extends MetricValues {
  node_id: number;
  hostname: string;
  display_name: string;
  role: NodeRole;
  ip_address: string;
  is_simulated: boolean;
  status: NodeStatus;
  timestamp: string;
  memory_total_mb: number;
  link_capacity_mbps: number;
  uptime_seconds: number;
  simulated_incident: AnomalyType | null;
}

export interface ClusterSummary {
  total_nodes: number;
  online: number;
  warning: number;
  critical: number;
  offline: number;
  avg_cpu_percent: number;
  avg_memory_percent: number;
  total_upload_kbps: number;
  total_download_kbps: number;
  unacknowledged_alerts: number;
}

// ---------------------------------------------------------------------------
// Anomaly alerts
// ---------------------------------------------------------------------------

export interface AnomalyAlertRead {
  id: number;
  node_id: number;
  detected_at: string;
  anomaly_type: AnomalyType;
  severity: AlertSeverity;
  metric_name: string;
  observed_value: number;
  baseline_mean: number | null;
  baseline_std: number | null;
  z_score: number | null;
  threshold: number;
  message: string;
  acknowledged: boolean;
  acknowledged_at: string | null;
  node_hostname: string | null;
}

export interface AlertPage {
  total: number;
  limit: number;
  offset: number;
  items: AnomalyAlertRead[];
}

export interface AlertQuery {
  node_id?: number;
  severity?: AlertSeverity;
  anomaly_type?: AnomalyType;
  acknowledged?: boolean;
  limit?: number;
  offset?: number;
}

// ---------------------------------------------------------------------------
// Port audits
// ---------------------------------------------------------------------------

export interface PortScanRequest {
  target: string;
  ports?: number[] | null;
  port_range?: [number, number] | null;
  timeout_seconds?: number | null;
  concurrency?: number | null;
  grab_banners?: boolean | null;
  node_id?: number | null;
}

export interface PortFindingRead {
  id: number;
  audit_id: number;
  port: number;
  protocol: "tcp";
  service: string;
  state: PortState;
  banner: string | null;
  response_ms: number | null;
  risk_level: RiskLevel;
  risk_reason: string;
  recommendation: string;
}

export interface PortAuditSummary {
  id: number;
  node_id: number | null;
  target_host: string;
  resolved_ip: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  host_reachable: boolean;
  host_latency_ms: number | null;
  total_ports_scanned: number;
  open_ports_count: number;
  risk_score: number;
  overall_risk: RiskLevel;
}

export interface PortAuditRead {
  id: number;
  node_id: number | null;
  target_host: string;
  resolved_ip: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  host_reachable: boolean;
  host_latency_ms: number | null;
  total_ports_scanned: number;
  open_ports_count: number;
  risk_score: number;
  overall_risk: RiskLevel;
  findings: PortFindingRead[];
}

// ---------------------------------------------------------------------------
// Simulation control, stream envelope and health
// ---------------------------------------------------------------------------

export interface IncidentInjectionRequest {
  hostname: string;
  anomaly_type: AnomalyType;
  /** 5 to 1800 seconds. */
  duration_seconds: number;
}

export interface IncidentInjectionResponse {
  hostname: string;
  anomaly_type: AnomalyType;
  duration_seconds: number;
  accepted: boolean;
}

/** One WebSocket frame from /ws/telemetry. */
export interface TelemetryBroadcast {
  type: "telemetry";
  timestamp: string;
  tick: number;
  summary: ClusterSummary;
  nodes: NodeTelemetry[];
  new_alerts: AnomalyAlertRead[];
}

export interface HealthResponse {
  status: "ok" | "degraded";
  app_name: string;
  version: string;
  environment: string;
  uptime_seconds: number;
  telemetry_ticks: number;
  websocket_clients: number;
  database: "ok" | "error";
}
