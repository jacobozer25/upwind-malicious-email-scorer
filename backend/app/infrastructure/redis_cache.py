"""
backend/app/infrastructure/redis_cache.py
------------------------------------------
Redis cache adapter with automatic in-memory fallback.

Design
======
* In production (Docker + Redis sidecar), ``REDIS_URL`` is set and a real
  ``redis.asyncio.Redis`` client is used for rate-limiting and semantic
  caching.
* In local venv development (no Redis), the module falls back to an
  **in-memory mock** that satisfies the same interface. The mock is
  intentionally simple — it is NOT a Redis replacement for production, but
  it keeps the application bootable and the rate-limit / cache code paths
  exercised so nothing breaks when you later wire up the real Redis.

Fallback behaviour
==================
* ``init_redis()`` tries to connect and PING Redis. If the connection fails
  (``ConnectionError``, ``OSError``, or any ``redis`` exception), it logs a
  prominent WARNING and installs the in-memory mock instead.
* ``get_redis()`` always returns a client — either the real one or the mock.
  Callers never need to check which one they have.
* ``close_redis()`` is a no-op for the mock (nothing to close).

In-memory mock limitations (intentional)
=========================================
* No TTL enforcement — keys live forever in the process.
* No persistence — data is lost on restart.
* Not thread-safe across processes — fine for a single-worker dev server.
* Rate-limit counters reset on restart — acceptable for local dev.

These limitations are clearly logged at startup so they are never silently
mistaken for production behaviour.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton — set by init_redis(), read by get_redis().
# ---------------------------------------------------------------------------
_redis_client: Any = None
_using_mock: bool = False


# ---------------------------------------------------------------------------
# In-memory mock that mirrors the redis.asyncio.Redis interface used by
# the rate-limiter and semantic cache.
# ---------------------------------------------------------------------------


class _InMemoryRedis:
    """Minimal async Redis mock backed by a plain dict.

    Implements only the commands used by this application:
    ``ping``, ``get``, ``set``, ``setex``, ``incr``, ``expire``,
    ``ttl``, ``delete``, ``exists``.

    All methods are ``async`` so they are drop-in replacements for the
    real redis.asyncio client.
    """

    def __init__(self) -> None:
        # {key: (value_bytes, expires_at_monotonic | None)}
        self._store: dict[str, tuple[bytes, float | None]] = {}

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_expired(self, key: str) -> bool:
        entry = self._store.get(key)
        if entry is None:
            return True
        _, expires_at = entry
        if expires_at is not None and time.monotonic() > expires_at:
            del self._store[key]
            return True
        return False

    def _get_raw(self, key: str) -> bytes | None:
        if self._is_expired(key):
            return None
        return self._store[key][0]

    # ── Redis commands ────────────────────────────────────────────────────────

    async def ping(self) -> bool:
        return True

    async def get(self, key: str) -> bytes | None:
        return self._get_raw(key)

    async def set(
        self,
        key: str,
        value: str | bytes | int,
        ex: int | None = None,
        px: int | None = None,
        nx: bool = False,
        xx: bool = False,
    ) -> bool:
        raw = value if isinstance(value, bytes) else str(value).encode()
        existing = self._get_raw(key)
        if nx and existing is not None:
            return False
        if xx and existing is None:
            return False
        expires_at: float | None = None
        if ex is not None:
            expires_at = time.monotonic() + ex
        elif px is not None:
            expires_at = time.monotonic() + px / 1000.0
        self._store[key] = (raw, expires_at)
        return True

    async def setex(self, key: str, seconds: int, value: str | bytes | int) -> bool:
        return await self.set(key, value, ex=seconds)

    async def incr(self, key: str) -> int:
        raw = self._get_raw(key)
        current = int(raw.decode()) if raw is not None else 0
        new_val = current + 1
        # Preserve existing TTL.
        expires_at = self._store[key][1] if key in self._store else None
        self._store[key] = (str(new_val).encode(), expires_at)
        return new_val

    async def expire(self, key: str, seconds: int) -> bool:
        if key not in self._store or self._is_expired(key):
            return False
        val, _ = self._store[key]
        self._store[key] = (val, time.monotonic() + seconds)
        return True

    async def ttl(self, key: str) -> int:
        if self._is_expired(key):
            return -2  # Key does not exist (Redis convention)
        _, expires_at = self._store[key]
        if expires_at is None:
            return -1  # No expiry
        remaining = expires_at - time.monotonic()
        return max(0, int(remaining))

    async def delete(self, *keys: str) -> int:
        deleted = 0
        for key in keys:
            if key in self._store:
                del self._store[key]
                deleted += 1
        return deleted

    async def exists(self, *keys: str) -> int:
        return sum(1 for k in keys if not self._is_expired(k))

    async def close(self) -> None:
        """No-op — nothing to close for the in-memory mock."""
        pass

    async def aclose(self) -> None:
        """Alias for close() — matches redis.asyncio interface."""
        pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def init_redis(settings: Any) -> None:
    """Initialise the Redis client (or fall back to the in-memory mock).

    Called once during application startup (lifespan). Sets the module-level
    ``_redis_client`` singleton used by ``get_redis()``.

    Parameters
    ----------
    settings:
        The application settings object. Must have a ``redis_url`` attribute.
        If ``redis_url`` is ``None`` or empty, the mock is used immediately
        without attempting a connection.
    """
    global _redis_client, _using_mock

    redis_url: str = getattr(settings, "redis_url", "") or ""

    if not redis_url:
        _install_mock("REDIS_URL is not set")
        return

    try:
        import redis.asyncio as aioredis  # type: ignore[import]

        client = aioredis.from_url(
            str(redis_url),
            encoding="utf-8",
            decode_responses=False,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        # Verify the connection is actually reachable.
        await asyncio.wait_for(client.ping(), timeout=3.0)
        _redis_client = client
        _using_mock = False
        log.info(
            "redis.connected",
            extra={"redis_url": _redact_url(str(redis_url))},
        )

    except ImportError:
        _install_mock("redis package is not installed (pip install redis[hiredis])")

    except (asyncio.TimeoutError, OSError, Exception) as exc:
        _install_mock(
            f"Redis unreachable at {_redact_url(str(redis_url))}: {type(exc).__name__}: {exc}"
        )


def _install_mock(reason: str) -> None:
    """Install the in-memory mock and emit a prominent warning."""
    global _redis_client, _using_mock
    _redis_client = _InMemoryRedis()
    _using_mock = True

    log.warning(
        "redis.fallback_to_in_memory_mock",
        extra={
            "reason": reason,
            "impact": (
                "Rate-limit counters and semantic cache are in-process only. "
                "Counters reset on restart. NOT suitable for production. "
                "Start Redis (docker run -p 6379:6379 redis:7-alpine) "
                "or set REDIS_URL to use the real cache."
            ),
        },
    )
    # Also print directly to stderr so it's visible even before structlog
    # is fully configured (e.g. during early startup).
    import sys
    print(
        f"\n⚠️  [redis_cache] FALLBACK TO IN-MEMORY MOCK — {reason}\n"
        "   Rate limits and cache are process-local only. "
        "Not suitable for production.\n",
        file=sys.stderr,
        flush=True,
    )


async def close_redis() -> None:
    """Close the Redis connection (no-op for the in-memory mock)."""
    global _redis_client, _using_mock
    if _redis_client is not None and not _using_mock:
        try:
            await _redis_client.aclose()
        except Exception:  # noqa: BLE001
            pass
    _redis_client = None
    _using_mock = False


def get_redis() -> Any:
    """Return the active Redis client (real or mock).

    Raises
    ------
    RuntimeError
        If called before ``init_redis()`` has been awaited.
    """
    if _redis_client is None:
        raise RuntimeError(
            "Redis client is not initialised. "
            "Ensure init_redis() is called during application startup."
        )
    return _redis_client


def is_using_mock() -> bool:
    """Return True if the in-memory mock is active (Redis is unavailable)."""
    return _using_mock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redact_url(url: str) -> str:
    """Remove password from a Redis URL for safe logging."""
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        if parsed.password:
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            if parsed.username:
                netloc = f"{parsed.username}:***@{netloc}"
            parsed = parsed._replace(netloc=netloc)
            return urlunparse(parsed)
    except Exception:  # noqa: BLE001
        pass
    return url
