"""Centralised application settings loaded from environment variables or a .env file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"


class Settings(BaseSettings):
    """Runtime configuration. Every field can be overridden with a NETPULSE_<FIELD> env var."""

    model_config = SettingsConfigDict(
        env_prefix="NETPULSE_",
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    app_name: str = "NetPulse SysGuard"
    app_version: str = "1.0.0"
    environment: str = "development"
    log_level: str = "INFO"
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
    )

    # Database
    database_url: str = f"sqlite+aiosqlite:///{(DATA_DIR / 'netpulse.db').as_posix()}"
    database_echo: bool = False

    # Telemetry pipeline
    telemetry_interval_seconds: float = Field(default=1.0, gt=0.1, le=60.0)
    metrics_persist_every_n_ticks: int = Field(default=5, ge=1, le=3600)
    metrics_retention_days: int = Field(default=7, ge=1, le=365)
    retention_check_interval_seconds: int = Field(default=3600, ge=60)
    host_link_capacity_mbps: float = Field(default=1000.0, gt=0)
    latency_probe_host: str = "1.1.1.1"
    latency_probe_port: int = Field(default=443, ge=1, le=65535)
    latency_probe_timeout_seconds: float = Field(default=1.0, gt=0, le=10)

    # Enterprise cluster simulator
    enable_simulator: bool = True
    simulator_seed: int | None = None
    simulator_incident_probability: float = Field(default=0.0015, ge=0.0, le=1.0)

    # Anomaly detection engine
    anomaly_window_size: int = Field(default=60, ge=10, le=3600)
    anomaly_min_samples: int = Field(default=20, ge=5)
    anomaly_zscore_threshold: float = Field(default=3.0, gt=0)
    anomaly_cpu_critical_percent: float = Field(default=90.0, gt=0, le=100)
    anomaly_memory_leak_window: int = Field(default=90, ge=20, le=3600)
    anomaly_memory_leak_min_slope: float = Field(default=0.08, gt=0)
    anomaly_memory_leak_min_r2: float = Field(default=0.85, gt=0, le=1)
    anomaly_bandwidth_saturation_percent: float = Field(default=85.0, gt=0, le=100)
    anomaly_latency_critical_ms: float = Field(default=250.0, gt=0)
    anomaly_disk_critical_percent: float = Field(default=92.0, gt=0, le=100)
    anomaly_cooldown_seconds: int = Field(default=60, ge=0)

    # Port scanner
    scan_default_timeout_seconds: float = Field(default=0.8, gt=0, le=10)
    scan_max_concurrency: int = Field(default=200, ge=1, le=2000)
    scan_max_ports: int = Field(default=1024, ge=1, le=65535)
    scan_allow_public_targets: bool = False
    scan_banner_grab: bool = True

    # WebSocket
    ws_max_clients: int = Field(default=50, ge=1)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide cached Settings instance."""
    return Settings()
