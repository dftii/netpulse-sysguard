FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NETPULSE_ENVIRONMENT=docker

LABEL org.opencontainers.image.title="NetPulse SysGuard Backend" \
      org.opencontainers.image.description="FastAPI API for telemetry, port auditing and anomaly detection in NetPulse SysGuard" \
      org.opencontainers.image.source="https://github.com/dftii/netpulse-sysguard" \
      org.opencontainers.image.url="https://github.com/dftii/netpulse-sysguard" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install runtime dependencies before copying the code so this layer stays cached
# until requirements.txt changes. Development requirements are never installed here.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application (run.py, seed.py, app/, ...). backend/.dockerignore excludes
# tests, caches, local databases and .env files from the build context.
COPY . .

# Run as an unprivileged user with a fixed uid so the volume ownership is predictable.
# Only the data directory is writable; the application code stays owned by root.
RUN groupadd --system --gid 10001 netpulse \
    && useradd --system --no-log-init --uid 10001 --gid netpulse \
        --home-dir /app --shell /usr/sbin/nologin netpulse \
    && mkdir -p /app/data \
    && chown netpulse:netpulse /app/data

VOLUME ["/app/data"]
USER netpulse

EXPOSE 8000

# python:3.12-slim has no curl, so the probe uses urllib. It exits non-zero unless the
# health endpoint answers 200. The proxy handler is disabled so that a proxy configured
# in the environment cannot intercept the loopback request.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import sys, urllib.request; opener = urllib.request.build_opener(urllib.request.ProxyHandler({})); resp = opener.open('http://127.0.0.1:8000/api/health', timeout=4); sys.exit(0 if resp.status == 200 else 1)"

# Exactly one worker is supported. The telemetry pipeline, the anomaly baselines, the
# cluster simulator and the WebSocket client registry all live in process memory, so
# multiple uvicorn workers would split that state and produce inconsistent results.
# run.py already forces workers=1; the port must match the HEALTHCHECK above.
CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8000"]
