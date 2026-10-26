"""Domain enumerations shared by ORM models, Pydantic schemas and services."""

from __future__ import annotations

from enum import StrEnum


class NodeRole(StrEnum):
    HOST = "host"
    DATABASE = "database"
    LOAD_BALANCER = "load_balancer"
    AI_COMPUTE = "ai_compute"
    FIREWALL = "firewall"
    WEB_SERVER = "web_server"
    CACHE = "cache"
    STORAGE = "storage"
    DOMAIN_CONTROLLER = "domain_controller"


class NodeStatus(StrEnum):
    ONLINE = "online"
    WARNING = "warning"
    CRITICAL = "critical"
    OFFLINE = "offline"


class RiskLevel(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class AnomalyType(StrEnum):
    CPU_SPIKE = "cpu_spike"
    MEMORY_LEAK = "memory_leak"
    BANDWIDTH_SATURATION = "bandwidth_saturation"
    CRITICAL_LATENCY = "critical_latency"
    DISK_PRESSURE = "disk_pressure"


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class ExportFormat(StrEnum):
    JSON = "json"
    CSV = "csv"
