"""
tests/unit/test_redis_cache.py
--------------------------------
Unit tests for the Redis cache adapter and in-memory mock fallback.

These tests verify:
1. The in-memory mock correctly implements the Redis interface.
2. ``init_redis()`` falls back to the mock when Redis is unreachable.
3. ``init_redis()`` falls back to the mock when REDIS_URL is not set.
4. ``get_redis()`` raises if called before ``init_redis()``.
5. ``is_using_mock()`` returns the correct state.
6. The rate-limit logic works correctly against the in-memory mock.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from app.infrastructure.redis_cache import (
    _InMemoryRedis,
    close_redis,
    get_redis,
    init_redis,
    is_using_mock,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeSettings:
    """Minimal settings stub."""

    def __init__(self, redis_url: str | None = None) -> None:
        self.redis_url = redis_url


# ---------------------------------------------------------------------------
# _InMemoryRedis unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestInMemoryRedis:
    async def test_ping_returns_true(self):
        r = _InMemoryRedis()
        assert await r.ping() is True

    async def test_set_and_get(self):
        r = _InMemoryRedis()
        await r.set("key", "value")
        result = await r.get("key")
        assert result == b"value"

    async def test_get_missing_key_returns_none(self):
        r = _InMemoryRedis()
        assert await r.get("nonexistent") is None

    async def test_set_with_expiry_and_ttl(self):
        r = _InMemoryRedis()
        await r.set("key", "val", ex=60)
        ttl = await r.ttl("key")
        assert 55 <= ttl <= 60

    async def test_expired_key_returns_none(self):
        r = _InMemoryRedis()
        await r.set("key", "val", ex=1)
        # Manually expire by manipulating the store.
        r._store["key"] = (b"val", time.monotonic() - 1)
        assert await r.get("key") is None

    async def test_incr_starts_at_one(self):
        r = _InMemoryRedis()
        count = await r.incr("counter")
        assert count == 1

    async def test_incr_increments(self):
        r = _InMemoryRedis()
        await r.incr("counter")
        await r.incr("counter")
        count = await r.incr("counter")
        assert count == 3

    async def test_expire_sets_ttl(self):
        r = _InMemoryRedis()
        await r.set("key", "val")
        result = await r.expire("key", 30)
        assert result is True
        ttl = await r.ttl("key")
        assert 25 <= ttl <= 30

    async def test_expire_missing_key_returns_false(self):
        r = _InMemoryRedis()
        result = await r.expire("nonexistent", 30)
        assert result is False

    async def test_delete_removes_key(self):
        r = _InMemoryRedis()
        await r.set("key", "val")
        deleted = await r.delete("key")
        assert deleted == 1
        assert await r.get("key") is None

    async def test_delete_multiple_keys(self):
        r = _InMemoryRedis()
        await r.set("a", "1")
        await r.set("b", "2")
        deleted = await r.delete("a", "b", "nonexistent")
        assert deleted == 2

    async def test_exists_returns_count(self):
        r = _InMemoryRedis()
        await r.set("a", "1")
        await r.set("b", "2")
        count = await r.exists("a", "b", "nonexistent")
        assert count == 2

    async def test_setex_sets_value_with_expiry(self):
        r = _InMemoryRedis()
        await r.setex("key", 60, "value")
        result = await r.get("key")
        assert result == b"value"
        ttl = await r.ttl("key")
        assert ttl > 0

    async def test_set_nx_does_not_overwrite(self):
        r = _InMemoryRedis()
        await r.set("key", "original")
        result = await r.set("key", "new", nx=True)
        assert result is False
        assert await r.get("key") == b"original"

    async def test_set_xx_requires_existing_key(self):
        r = _InMemoryRedis()
        result = await r.set("key", "val", xx=True)
        assert result is False
        assert await r.get("key") is None

    async def test_ttl_no_expiry_returns_minus_one(self):
        r = _InMemoryRedis()
        await r.set("key", "val")
        assert await r.ttl("key") == -1

    async def test_ttl_missing_key_returns_minus_two(self):
        r = _InMemoryRedis()
        assert await r.ttl("nonexistent") == -2

    async def test_close_is_noop(self):
        r = _InMemoryRedis()
        await r.close()  # Should not raise
        await r.aclose()  # Should not raise

    async def test_incr_preserves_ttl(self):
        """incr() must not reset the TTL of an existing key."""
        r = _InMemoryRedis()
        await r.set("counter", "0", ex=60)
        await r.incr("counter")
        ttl = await r.ttl("counter")
        assert ttl > 0  # TTL was preserved


# ---------------------------------------------------------------------------
# init_redis / fallback tests
# ---------------------------------------------------------------------------


class TestInitRedis:
    """Tests for init_redis() fallback behaviour.

    Uses synchronous setup/teardown to avoid the async-fixture-in-sync-test
    issue with pytest-asyncio 1.x. Each test calls close_redis() explicitly
    at the start and end.
    """

    @pytest.mark.asyncio
    async def test_no_redis_url_uses_mock(self):
        """When REDIS_URL is not set, the mock is installed."""
        await close_redis()
        await init_redis(_FakeSettings(redis_url=None))
        assert is_using_mock() is True
        redis = get_redis()
        assert isinstance(redis, _InMemoryRedis)
        await close_redis()

    @pytest.mark.asyncio
    async def test_empty_redis_url_uses_mock(self):
        """When REDIS_URL is empty string, the mock is installed."""
        await close_redis()
        await init_redis(_FakeSettings(redis_url=""))
        assert is_using_mock() is True
        await close_redis()

    @pytest.mark.asyncio
    async def test_unreachable_redis_url_uses_mock(self):
        """When Redis is unreachable, the mock is installed (no crash)."""
        await close_redis()
        await init_redis(_FakeSettings(redis_url="redis://127.0.0.1:19999/0"))
        assert is_using_mock() is True
        redis = get_redis()
        assert isinstance(redis, _InMemoryRedis)
        await close_redis()

    @pytest.mark.asyncio
    async def test_get_redis_before_init_raises(self):
        """get_redis() raises RuntimeError if called before init_redis()."""
        await close_redis()
        with pytest.raises(RuntimeError, match="not initialised"):
            get_redis()

    @pytest.mark.asyncio
    async def test_close_redis_resets_state(self):
        """close_redis() resets the singleton so get_redis() raises again."""
        await close_redis()
        await init_redis(_FakeSettings(redis_url=None))
        assert get_redis() is not None
        await close_redis()
        with pytest.raises(RuntimeError):
            get_redis()

    @pytest.mark.asyncio
    async def test_mock_is_functional_after_fallback(self):
        """The mock returned after fallback is fully functional."""
        await close_redis()
        await init_redis(_FakeSettings(redis_url=None))
        redis = get_redis()
        await redis.set("test_key", "hello")
        result = await redis.get("test_key")
        assert result == b"hello"
        await close_redis()


# ---------------------------------------------------------------------------
# Rate-limit integration with the mock
# ---------------------------------------------------------------------------


class TestRateLimitWithMock:
    """Rate-limit tests using the in-memory mock.

    Each test manages its own Redis lifecycle to avoid async-fixture issues.
    """

    @pytest.mark.asyncio
    async def test_rate_limit_check_passes_under_limit(self):
        """check_rate_limit() passes when under the limit."""
        from app.core.rate_limit import check_rate_limit  # noqa: PLC0415

        await close_redis()
        await init_redis(_FakeSettings(redis_url=None))
        redis = get_redis()
        await check_rate_limit("user123", redis, limit_per_minute=5, limit_per_day=100)
        await close_redis()

    @pytest.mark.asyncio
    async def test_rate_limit_check_raises_on_minute_exceeded(self):
        """check_rate_limit() raises HTTP 429 when minute limit is exceeded."""
        from fastapi import HTTPException  # noqa: PLC0415
        from app.core.rate_limit import check_rate_limit  # noqa: PLC0415

        await close_redis()
        await init_redis(_FakeSettings(redis_url=None))
        redis = get_redis()

        for _ in range(3):
            await check_rate_limit("user_x", redis, limit_per_minute=3, limit_per_day=1000)

        with pytest.raises(HTTPException) as exc_info:
            await check_rate_limit("user_x", redis, limit_per_minute=3, limit_per_day=1000)

        assert exc_info.value.status_code == 429
        await close_redis()

    @pytest.mark.asyncio
    async def test_rate_limit_different_users_are_independent(self):
        """Rate limits are per-user — different users don't share counters."""
        from app.core.rate_limit import check_rate_limit  # noqa: PLC0415

        await close_redis()
        await init_redis(_FakeSettings(redis_url=None))
        redis = get_redis()

        for _ in range(3):
            await check_rate_limit("user_a", redis, limit_per_minute=3, limit_per_day=1000)

        await check_rate_limit("user_b", redis, limit_per_minute=3, limit_per_day=1000)
        await close_redis()
