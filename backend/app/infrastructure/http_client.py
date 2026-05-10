"""
backend/app/infrastructure/http_client.py
------------------------------------------
Shared httpx async client with timeouts, retries, and no-redirect policy.

This module is intentionally minimal — it provides a single shared
``httpx.AsyncClient`` instance that is initialised at startup and closed
at shutdown. All outbound HTTP calls (reputation feeds, etc.) must go
through this client so that the timeout and redirect policies are enforced
consistently.

SSRF note
=========
The client is configured with ``follow_redirects=False``. Callers that need
to follow redirects must do so explicitly and only to allowlisted hosts.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

_http_client: Any = None


async def init_http_client(settings: Any) -> None:
    """Initialise the shared httpx async client."""
    global _http_client
    try:
        import httpx  # type: ignore[import]

        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=5.0,
                read=10.0,
                write=5.0,
                pool=5.0,
            ),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        log.info("http_client.initialised")
    except ImportError:
        log.warning(
            "http_client.httpx_not_installed",
            extra={"detail": "httpx is not installed; outbound HTTP calls will fail."},
        )
        _http_client = None


async def close_http_client() -> None:
    """Close the shared httpx async client."""
    global _http_client
    if _http_client is not None:
        try:
            await _http_client.aclose()
        except Exception:  # noqa: BLE001
            pass
        _http_client = None
        log.info("http_client.closed")


def get_http_client() -> Any:
    """Return the shared httpx async client.

    Raises
    ------
    RuntimeError
        If called before ``init_http_client()`` has been awaited.
    """
    if _http_client is None:
        raise RuntimeError(
            "HTTP client is not initialised. "
            "Ensure init_http_client() is called during application startup."
        )
    return _http_client
