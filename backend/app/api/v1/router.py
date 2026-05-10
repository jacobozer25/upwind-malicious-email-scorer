"""
backend/app/api/v1/router.py
------------------------------
API v1 router — aggregates all v1 endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter

api_router = APIRouter()

# Health endpoint is always registered.
try:
    from app.api.v1.endpoints.health import router as health_router  # noqa: PLC0415
    api_router.include_router(health_router, tags=["health"])
except ImportError:
    pass

# Analyze endpoint — registered if the module exists.
try:
    from app.api.v1.endpoints.analyze import router as analyze_router  # noqa: PLC0415
    api_router.include_router(analyze_router, tags=["analyze"])
except ImportError:
    pass
