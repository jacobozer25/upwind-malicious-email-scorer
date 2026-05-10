"""
backend/app/main.py
-------------------
FastAPI application factory for the Malicious Email Scorer.

Design notes
============
* `create_app()` is a *factory* — it never executes at import time. This makes
  the app cheap to import for tests and lets us inject a different settings
  object (e.g. for integration tests with a fake LLM provider).
* Boot-time failures are handled gracefully:
  - Redis unavailable → falls back to in-memory mock (logged as WARNING).
  - LLM provider not configured → falls back to deterministic-only mode.
  - The app NEVER crashes on missing Redis or missing LLM key in dev mode.
* No business logic lives in this file. Routing is delegated to
  `app.api.v1.router`, cross-cutting concerns to `app.core.*`, and the
  actual analysis to `app.services.email_analyzer`.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.middleware import RequestIdMiddleware, SecurityHeadersMiddleware
from app.api.v1.router import api_router
from app.config import Settings, get_settings
from app.core.exceptions import AppError, app_error_handler, unhandled_error_handler
from app.core.logging import configure_logging
from app.infrastructure.http_client import close_http_client, init_http_client
from app.infrastructure.redis_cache import close_redis, init_redis
from app.llm.client import get_llm_provider

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan: deterministic startup / shutdown ordering.
# ─────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings

    # Order matters: logging first, so failures during init are observable.
    configure_logging(settings)
    log.info("startup.begin", extra={"env": settings.environment})

    # ── LLM provider ─────────────────────────────────────────────────────────
    # get_llm_provider() never raises — it returns a no-op provider if the
    # LLM is not configured. The healthcheck() on the no-op is also a no-op.
    try:
        provider = get_llm_provider(settings)
        await provider.healthcheck()
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "startup.llm_healthcheck_failed",
            extra={"error": str(exc), "detail": "Continuing in deterministic-only mode."},
        )

    # ── HTTP client ───────────────────────────────────────────────────────────
    # init_http_client() is best-effort — if httpx is not installed, it logs
    # a warning and sets the client to None.
    await init_http_client(settings)

    # ── Redis ─────────────────────────────────────────────────────────────────
    # init_redis() NEVER raises. If Redis is unreachable or REDIS_URL is not
    # set, it installs the in-memory mock and logs a prominent WARNING.
    # The application continues to serve requests using the mock.
    await init_redis(settings)

    log.info("startup.complete")
    try:
        yield
    finally:
        log.info("shutdown.begin")
        await close_http_client()
        await close_redis()
        log.info("shutdown.complete")


# ─────────────────────────────────────────────────────────────────────────────
# App factory.
# ─────────────────────────────────────────────────────────────────────────────
def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI app.

    Pass ``settings`` to override env-loaded config (used by tests). In
    production, ``Settings()`` is constructed from env vars and validated by
    pydantic-settings.
    """
    settings = settings or get_settings()

    app = FastAPI(
        title="Malicious Email Scorer",
        version="1.0.0",
        docs_url="/docs" if settings.expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.expose_docs else None,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # ── Middleware (order matters: outermost first) ─────────────────────────
    # 1. Request-id: tags every log line for correlation.
    app.add_middleware(RequestIdMiddleware)
    # 2. Security headers: CSP, HSTS, X-Content-Type-Options, etc.
    app.add_middleware(SecurityHeadersMiddleware)
    # 3. CORS: closed by default; only the Apps Script origin is allowed.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=False,
        allow_methods=["POST", "GET", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        max_age=600,
    )

    # ── Exception handlers ──────────────────────────────────────────────────
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)

    # ── Routers ─────────────────────────────────────────────────────────────
    app.include_router(api_router, prefix="/v1")

    return app


# ASGI entry point: `uvicorn app.main:app`
app = create_app()
