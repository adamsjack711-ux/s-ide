# Multi-stage build for the headless Docker deployment.
#
# Stage 1 compiles the React/Vite frontend so the final Python image can serve
# the UI at http://<host>:8765/ alongside the API. The Node toolchain stays in
# Stage 1 and never lands in the runtime image — only the static dist/ output
# is copied across.
#
# Build context expected: repo root (see docker-compose.yml). This Dockerfile
# references paths under backend/ and frontend/ from that root.

# ── Stage 1 ── Build the React UI ─────────────────────────────────────────────
FROM node:20-slim AS frontend-builder

WORKDIR /build

# Cache deps separately from sources so source-only edits don't reinstall.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./

# Empty VITE_BACKEND_URL → api.ts falls back to same-origin (relative URLs),
# so the bundle works whatever hostname the operator points a browser at.
ENV VITE_BACKEND_URL=""
RUN npm run build


# ── Stage 2 ── Python runtime ────────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NT_BACKEND_HOST=0.0.0.0 \
    NT_BACKEND_PORT=8765

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        iproute2 \
        iputils-ping \
        lsof \
        net-tools \
        nmap \
        openssl \
        sudo \
        tcpdump \
        traceroute \
        whois \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements-bundle.txt /tmp/requirements-bundle.txt
RUN pip install -r /tmp/requirements-bundle.txt

COPY backend/ /app/

# Bring in the built UI. main.py mounts /app/frontend_dist at "/" only when
# the directory exists, so the PyInstaller Electron build (which has no UI
# bundle next to it) is unaffected by this addition.
COPY --from=frontend-builder /build/dist /app/frontend_dist

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8765/health || exit 1

CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8765", \
     "--log-level", "warning", \
     "--loop", "asyncio", "--http", "h11", "--ws", "wsproto"]
