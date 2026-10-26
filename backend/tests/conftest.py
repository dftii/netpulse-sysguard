"""Shared test configuration: isolate every test run on a throwaway SQLite database."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TEST_DB_DIR = Path(tempfile.mkdtemp(prefix="netpulse_test_"))

# Must be set before `app.config` / `app.database` are imported anywhere.
os.environ["NETPULSE_DATABASE_URL"] = f"sqlite+aiosqlite:///{(_TEST_DB_DIR / 'test.db').as_posix()}"
os.environ["NETPULSE_SIMULATOR_SEED"] = "1234"
os.environ["NETPULSE_SIMULATOR_INCIDENT_PROBABILITY"] = "0"
os.environ["NETPULSE_METRICS_PERSIST_EVERY_N_TICKS"] = "1"
os.environ["NETPULSE_LATENCY_PROBE_HOST"] = "127.0.0.1"
os.environ["NETPULSE_LATENCY_PROBE_PORT"] = "9"
os.environ["NETPULSE_LATENCY_PROBE_TIMEOUT_SECONDS"] = "0.2"
