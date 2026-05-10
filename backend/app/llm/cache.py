"""
backend/app/llm/cache.py
--------------------------
Semantic cache for LLM responses.

Uses the existing Redis connection (``app.infrastructure.redis_cache``) to
cache LLM verdicts keyed by a SHA-256 hash of the normalized prompt input.

Cache key
=========
The cache key is derived from a deterministic hash of:
  - The sanitized email body (truncated to 16 kB)
  - The serialized deterministic findings (sorted for stability)
  - The LLM model name (so model upgrades invalidate the cache)

This means two emails with identical content and findings will hit the same
cache entry, regardless of metadata like timestamps or message IDs.

TTL
===
Default TTL is 24 hours.  Verdicts older than 24 hours are re-analyzed to
account for evolving threat intelligence (e.g. a URL that was clean
yesterday may be flagged today).

Logging
=======
Every cache lookup logs "Cache Hit" or "Cache Miss" at DEBUG level for
debugging and performance monitoring.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TTL_SECONDS: int = 24 * 60 * 60  # 24 hours
_CACHE_KEY_PREFIX: str = "llm_verdict:"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def get_cached_verdict(
    body: str,
    findings: list[dict[str, Any]],
    model: str,
) -> dict[str, Any] | None:
    """Look up a cached LLM verdict.

    Args:
        body: The sanitized email body (after sanitizer.py processing).
        findings: The serialized deterministic findings list.
        model: The LLM model name (e.g. "claude-3-5-sonnet-20240620").

    Returns:
        The cached verdict dict if found, or ``None`` on a cache miss.
    """
    key = _build_cache_key(body, findings, model)

    try:
        from app.infrastructure.redis_cache import get_cache  # noqa: PLC0415
        cache = get_cache()
        raw = await cache.get(key)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "llm_cache.get_error",
            extra={"key": key[:20], "error": str(exc)[:200]},
        )
        return None

    if raw is None:
        log.debug("llm_cache.miss", extra={"key": key[:20]})
        return None

    try:
        verdict = json.loads(raw)
        log.debug(
            "llm_cache.hit",
            extra={
                "key": key[:20],
                "verdict": verdict.get("verdict"),
                "semantic_score": verdict.get("semantic_score"),
            },
        )
        return verdict
    except (json.JSONDecodeError, TypeError) as exc:
        log.warning(
            "llm_cache.decode_error",
            extra={"key": key[:20], "error": str(exc)},
        )
        return None


async def set_cached_verdict(
    body: str,
    findings: list[dict[str, Any]],
    model: str,
    verdict: dict[str, Any],
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> None:
    """Store an LLM verdict in the cache.

    Args:
        body: The sanitized email body.
        findings: The serialized deterministic findings list.
        model: The LLM model name.
        verdict: The validated verdict dict to cache.
        ttl_seconds: Cache TTL in seconds. Defaults to 24 hours.
    """
    key = _build_cache_key(body, findings, model)

    try:
        from app.infrastructure.redis_cache import get_cache  # noqa: PLC0415
        cache = get_cache()
        await cache.set(key, json.dumps(verdict), ttl=ttl_seconds)
        log.debug(
            "llm_cache.stored",
            extra={
                "key": key[:20],
                "ttl_seconds": ttl_seconds,
                "verdict": verdict.get("verdict"),
            },
        )
    except Exception as exc:  # noqa: BLE001
        # Cache write failures are non-fatal — the verdict is still returned.
        log.warning(
            "llm_cache.set_error",
            extra={"key": key[:20], "error": str(exc)[:200]},
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _build_cache_key(
    body: str,
    findings: list[dict[str, Any]],
    model: str,
) -> str:
    """Build a deterministic cache key from the input components.

    The key is a SHA-256 hash of the JSON-serialized inputs, prefixed with
    ``llm_verdict:`` for namespace isolation in Redis.

    Args:
        body: The sanitized email body.
        findings: The deterministic findings list (will be sorted for stability).
        model: The LLM model name.

    Returns:
        A Redis key string of the form ``llm_verdict:<hex_hash>``.
    """
    # Sort findings by a stable key to ensure identical findings in different
    # orders produce the same cache key.
    try:
        sorted_findings = sorted(
            findings,
            key=lambda f: json.dumps(f, sort_keys=True),
        )
    except (TypeError, ValueError):
        sorted_findings = findings

    payload = json.dumps(
        {
            "body": body,
            "findings": sorted_findings,
            "model": model,
        },
        sort_keys=True,
        ensure_ascii=False,
    )

    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{_CACHE_KEY_PREFIX}{digest}"
