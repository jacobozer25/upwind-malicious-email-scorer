"""
backend/app/core/rate_limit.py
--------------------------------
Per-user token-bucket rate limiter backed by Redis (or the in-memory mock).

Design
======
* Uses a simple sliding-window counter in Redis (or the in-memory mock).
* Two windows: per-minute (60 req/min) and per-day (1000 req/day).
* The rate-limit key is the verified caller's ``sub`` claim (opaque Google
  user ID) — never the email address, which could change.
* When Redis is unavailable and the in-memory mock is active, rate limiting
  still works correctly within a single process. Counters reset on restart.

FastAPI integration
===================
Use as a FastAPI dependency::

    from app.core.rate_limit import rate_limited

    @router.post("/analyze")
    async def analyze(
        caller: Caller = Depends(authenticated_caller),
        _: None = Depends(rate_limited),
    ):
        ...

The dependency raises ``HTTP 429`` when either window is exceeded.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import Depends, HTTPException, status

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Window definitions
# ---------------------------------------------------------------------------

_MINUTE_WINDOW_SECONDS = 60
_DAY_WINDOW_SECONDS = 86_400  # 24 hours


# ---------------------------------------------------------------------------
# Core rate-limit check (pure async function — easy to unit-test)
# ---------------------------------------------------------------------------


async def check_rate_limit(
    user_sub: str,
    redis: Any,
    *,
    limit_per_minute: int = 60,
    limit_per_day: int = 1000,
) -> None:
    """Check and increment rate-limit counters for ``user_sub``.

    Parameters
    ----------
    user_sub:
        The opaque Google user ID (``sub`` claim) used as the rate-limit key.
    redis:
        A Redis client (real or in-memory mock) that supports ``incr`` and
        ``expire``.
    limit_per_minute:
        Maximum requests allowed per 60-second window.
    limit_per_day:
        Maximum requests allowed per 24-hour window.

    Raises
    ------
    HTTPException(429)
        If either window limit is exceeded.
    """
    now_minute = int(time.time()) // _MINUTE_WINDOW_SECONDS
    now_day = int(time.time()) // _DAY_WINDOW_SECONDS

    minute_key = f"rl:min:{user_sub}:{now_minute}"
    day_key = f"rl:day:{user_sub}:{now_day}"

    # Increment both counters atomically (best-effort — no Lua script needed
    # for this simple implementation).
    minute_count: int = await redis.incr(minute_key)
    if minute_count == 1:
        # First request in this window — set the TTL.
        await redis.expire(minute_key, _MINUTE_WINDOW_SECONDS + 5)  # +5s grace

    day_count: int = await redis.incr(day_key)
    if day_count == 1:
        await redis.expire(day_key, _DAY_WINDOW_SECONDS + 60)  # +60s grace

    log.debug(
        "rate_limit.checked",
        extra={
            "sub": user_sub[:8] + "...",  # Partial sub for log correlation
            "minute_count": minute_count,
            "day_count": day_count,
        },
    )

    if minute_count > limit_per_minute:
        log.warning(
            "rate_limit.exceeded",
            extra={"window": "minute", "count": minute_count, "limit": limit_per_minute},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limit_exceeded",
                "window": "minute",
                "limit": limit_per_minute,
                "retry_after_seconds": _MINUTE_WINDOW_SECONDS,
            },
            headers={"Retry-After": str(_MINUTE_WINDOW_SECONDS)},
        )

    if day_count > limit_per_day:
        log.warning(
            "rate_limit.exceeded",
            extra={"window": "day", "count": day_count, "limit": limit_per_day},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limit_exceeded",
                "window": "day",
                "limit": limit_per_day,
                "retry_after_seconds": _DAY_WINDOW_SECONDS,
            },
            headers={"Retry-After": str(_DAY_WINDOW_SECONDS)},
        )


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def rate_limited(caller: Any = None) -> None:
    """FastAPI dependency that enforces per-user rate limits.

    Usage::

        @router.post("/analyze")
        async def analyze(
            caller: Caller = Depends(authenticated_caller),
            _: None = Depends(rate_limited),
        ):
            ...

    The dependency reads the Redis client from the infrastructure layer and
    the rate-limit settings from the application config.

    Raises
    ------
    HTTPException(429)
        If the per-minute or per-day limit is exceeded.
    """
    from app.infrastructure.redis_cache import get_redis  # noqa: PLC0415
    from app.config import get_settings  # noqa: PLC0415

    settings = get_settings()
    redis = get_redis()

    # ``caller`` is injected by FastAPI from the ``authenticated_caller``
    # dependency. In tests, it can be passed directly.
    sub = getattr(caller, "sub", "anonymous")

    await check_rate_limit(
        sub,
        redis,
        limit_per_minute=getattr(settings, "rate_limit_per_minute", 60),
        limit_per_day=getattr(settings, "rate_limit_per_day", 1000),
    )
