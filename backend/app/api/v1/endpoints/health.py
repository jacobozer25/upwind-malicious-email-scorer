"""
backend/app/api/v1/endpoints/health.py
----------------------------------------
GET /v1/healthz — liveness + readiness probe.
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/healthz", summary="Liveness and readiness probe")
async def healthz() -> JSONResponse:
    """Return 200 OK with basic service status.

    Used by load balancers and container orchestrators to determine if the
    service is alive and ready to serve traffic.
    """
    from app.infrastructure.redis_cache import is_using_mock  # noqa: PLC0415

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "version": "1.0.0",
            "redis": "mock (in-memory)" if is_using_mock() else "connected",
        },
    )
