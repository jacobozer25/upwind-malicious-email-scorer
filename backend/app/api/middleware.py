"""
backend/app/api/middleware.py
------------------------------
ASGI middleware: request-id injection and security headers.
"""
from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Inject a unique ``X-Request-ID`` header into every request and response.

    If the client already sends an ``X-Request-ID`` header, we use it (so
    distributed tracing works). Otherwise we generate a new UUID4.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        # Attach to request state so downstream code can log it.
        request.state.request_id = request_id
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security-related HTTP response headers to every response.

    Headers added
    =============
    * ``X-Content-Type-Options: nosniff`` — prevent MIME sniffing.
    * ``X-Frame-Options: DENY`` — prevent clickjacking.
    * ``Referrer-Policy: no-referrer`` — don't leak the URL in Referer.
    * ``Permissions-Policy`` — disable unused browser features.
    * ``Cache-Control: no-store`` — don't cache API responses.
    * ``Strict-Transport-Security`` — enforce HTTPS (1 year).
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response


# Fix missing import
from typing import Any  # noqa: E402
