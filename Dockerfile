# ──────────────────────────────────────────────────────────────────────────────
# Dockerfile — SlangHunter multi-stage production build
#
# Stage 1 (builder): installs the [api] extras into an isolated prefix so
#   only the compiled wheel tree is carried into the runtime stage — no build
#   toolchain bleeds into the final image.
#
# Stage 2 (runtime): minimal python:3.12-slim image running as a non-root
#   user. The src/ package is bind-copied (not pip-installed) because the
#   project uses a flat src/ layout without a src-layout hatch config, so
#   `from src import SlangHunter` requires /app on PYTHONPATH.
#
# PYTHONPATH caveat:  api/main.py uses `from src import SlangHunter`, which
#   means Python must find the `src` package at the top-level /app directory.
#   ENV PYTHONPATH=/app satisfies this without modifying application code.
#   Agents S4/S5: if the package is migrated to a proper src-layout install
#   (hatch tool.hatch.build.sources), PYTHONPATH can be removed.
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Copy packaging metadata first to maximise Docker layer caching.
# These files change far less frequently than application source code.
COPY pyproject.toml README.md LICENSE ./

# Copy the package source so hatchling can resolve the package during install.
COPY src/ ./src/

# Install [api] extras (fastapi, uvicorn, pydantic) into a dedicated prefix.
# --no-cache-dir keeps the builder layer lean; --prefix=/install isolates the
# installation tree so we can COPY only the built artifacts to runtime.
RUN pip install --no-cache-dir --prefix=/install ".[api]"


# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security hardening: create a dedicated non-root user so the process cannot
# write to system paths even if a dependency vulnerability is exploited.
RUN useradd --create-home --shell /bin/bash slanghunter

# Bring in the installed packages from the builder stage.
# Copying /install → /usr/local merges site-packages into the system prefix
# that Python 3.12-slim already uses, so no PYTHONPATH tweak is needed for
# third-party packages (fastapi, uvicorn, pydantic).
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application source directories.
# src/   — SlangHunter core engine (not a formally installed package; see note)
# api/   — FastAPI application layer
# data/  — JSON knowledge-base files (drugs, money_laundering, surikae)
COPY src/ ./src/
COPY api/ ./api/
COPY data/ ./data/

# Transfer ownership before switching user; chown on an already-owned path
# is a no-op but makes the intent explicit for auditors.
RUN chown -R slanghunter:slanghunter /app

USER slanghunter

# Port the API listens on — matches uvicorn CMD below.
EXPOSE 8000

# Runtime behaviour flags:
#   PYTHONUNBUFFERED=1    — stdout/stderr lines appear immediately in `docker logs`
#   PYTHONDONTWRITEBYTECODE=1 — prevent .pyc files cluttering the container FS
#   PYTHONPATH=/app       — allows `from src import SlangHunter` to resolve
#                           because `src` is a package directory under /app
#   PORT=8000             — informational; referenced by some PaaS platforms
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PORT=8000

# Liveness probe: the /health endpoint is a lightweight GET that returns 200
# when the FastAPI app and SlangHunter singleton are fully initialised.
# Use the Python standard library so the runtime image stays lean and does not
# depend on curl being present in python:3.12-slim.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default process: run uvicorn bound to all interfaces on port 8000.
# Using the exec-form array avoids a shell wrapper process (PID 1 = uvicorn).
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
