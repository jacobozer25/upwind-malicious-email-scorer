# =============================================================================
# backend/Dockerfile
# Multi-stage build for the Malicious Email Scorer FastAPI backend.
#
# Stages
# ======
# 1. builder  — installs Python dependencies into a venv (no dev tools in prod)
# 2. runtime  — copies only the venv + app code into a slim final image
#
# Security hardening
# ==================
# * Runs as non-root user (uid 1000) — never root in production.
# * Read-only root filesystem compatible (tmp dirs mounted at runtime).
# * No shell in the final image (python:3.11-slim still has sh, but the
#   entrypoint does not use it).
# * No secrets baked in — all config via environment variables at runtime.
# * .dockerignore excludes .env, __pycache__, .pytest_cache, tests/, etc.
#
# Build
# =====
#   docker build -t email-scorer-backend .
#
# Run (local dev)
# ===============
#   docker run --env-file .env -p 8080:8080 email-scorer-backend
# =============================================================================

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Install build tools needed for some Python packages (e.g. hiredis C extension).
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment so we can copy it cleanly to the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only requirements first to leverage Docker layer caching.
COPY requirements.txt /tmp/requirements.txt

# Install runtime dependencies (no dev/test extras).
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt


# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# ── Security: create a non-root user ─────────────────────────────────────────
RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 --gid appgroup --no-create-home --shell /sbin/nologin appuser

# Copy the virtual environment from the builder stage.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory.
WORKDIR /app

# Copy application source code.
# .dockerignore excludes: .env, __pycache__, .pytest_cache, tests/, *.pyc
COPY app/ ./app/

# ── Read-only filesystem support ──────────────────────────────────────────────
# Create /tmp as a writable directory for any temp files (e.g. structlog).
# In production, mount this as a tmpfs volume:
#   docker run --tmpfs /tmp:rw,noexec,nosuid,size=64m ...
RUN mkdir -p /tmp && chown appuser:appgroup /tmp

# ── Switch to non-root user ───────────────────────────────────────────────────
USER appuser

# ── Runtime configuration ─────────────────────────────────────────────────────
# All secrets and config are injected via environment variables at runtime.
# Do NOT set ANTHROPIC_API_KEY or OPENAI_API_KEY here.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# Expose the application port.
EXPOSE 8080

# ── Health check ──────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/v1/healthz')" \
    || exit 1

# ── Entrypoint ────────────────────────────────────────────────────────────────
# Use exec form (no shell) so signals are forwarded correctly to uvicorn.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "1", \
     "--log-level", "info", \
     "--no-access-log"]
