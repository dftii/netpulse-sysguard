"""Development / single-host production entry point: `python run.py`."""

from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the NetPulse SysGuard API server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes (development only)")
    args = parser.parse_args()

    # A single worker is required: the telemetry pipeline, detector baselines and
    # WebSocket registry live in process memory.
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload, workers=1)


if __name__ == "__main__":
    main()
