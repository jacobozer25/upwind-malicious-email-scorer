"""
backend/app/core/exceptions.py
--------------------------------
Application exception taxonomy and global FastAPI exception handlers.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)


class AppError(Exception):
    """Base class for all application-level errors.

    Attributes
    ----------
    status_code:
        HTTP status code to return.
    error_code:
        Machine-readable error code (stable across releases).
    detail:
        Human-readable detail message (may be shown to the caller).
    """

    status_code: int = 500
    error_code: str = "internal_error"

    def __init__(self, detail: str = "", **extra: Any) -> None:
        super().__init__(detail)
        self.detail = detail
        self.extra = extra


class AuthenticationError(AppError):
    status_code = 401
    error_code = "authentication_error"


class RateLimitError(AppError):
    status_code = 429
    error_code = "rate_limit_exceeded"


class ValidationError(AppError):
    status_code = 422
    error_code = "validation_error"


class UpstreamError(AppError):
    """Raised when an upstream service (LLM, reputation feed) is unavailable."""
    status_code = 503
    error_code = "upstream_unavailable"


# ---------------------------------------------------------------------------
# FastAPI exception handlers
# ---------------------------------------------------------------------------


async def app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle AppError subclasses — return a structured JSON error response."""
    err = exc if isinstance(exc, AppError) else AppError(str(exc))
    log.warning(
        "app_error",
        extra={
            "error_code": err.error_code,
            "status_code": err.status_code,
            "detail": err.detail,
            "path": str(request.url.path),
        },
    )
    return JSONResponse(
        status_code=err.status_code,
        content={
            "error": err.error_code,
            "detail": err.detail,
        },
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unexpected exceptions.

    Logs the full traceback but returns a generic 500 to the caller so
    internal details are never leaked.
    """
    log.error(
        "unhandled_error",
        extra={"path": str(request.url.path), "error": str(exc)},
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "detail": "An unexpected error occurred. Please try again later.",
        },
    )
