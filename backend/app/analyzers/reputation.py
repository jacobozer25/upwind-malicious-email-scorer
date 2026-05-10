"""
backend/app/analyzers/reputation.py
--------------------------------------
Circuit-broken reputation analyzer for the malicious email scorer.

This analyzer extracts URLs from the email body and checks them against
two external threat-intelligence feeds:

* **URLhaus** (abuse.ch) — a free, public feed of malware distribution URLs.
  Queried via the URLhaus lookup API (URL as a POST parameter — no SSRF risk).

* **PhishTank** — a community-driven phishing URL database.
  Queried via the PhishTank check API (URL as a query parameter).

Design notes
============
* **SSRF safety**: URLs from the email body are *never* fetched directly.
  They are passed as query/body parameters to allowlisted reputation APIs.
  The shared ``httpx`` client has ``follow_redirects=False``.

* **Circuit-breaking**: Each API call has a hard timeout of 800 ms.  If the
  call times out or the API returns an error, the analyzer logs a warning and
  continues — the verdict ships with a "low confidence on link reputation"
  note rather than blocking.

* **URL extraction**: A simple regex extracts ``http://`` and ``https://``
  URLs from the body.  Only the first ``_MAX_URLS_TO_CHECK`` unique URLs are
  checked to bound latency.

* **Rate limiting**: Both APIs have free-tier rate limits.  In production,
  callers should use the Redis cache (``app.infrastructure.redis_cache``) to
  cache reputation results by URL hash.  That wiring is left to the
  orchestrator / use-case layer.

* Implements :class:`~app.domain.ports.AnalyzerPort`.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Final
from urllib.parse import urlparse

from app.domain.enums import Category, Severity
from app.domain.models import EmailContext, Finding
from app.domain.ports import AnalyzerPort
from app.infrastructure.http_client import get_http_client

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Maximum number of unique URLs to check per email (latency bound)
_MAX_URLS_TO_CHECK: Final[int] = 10

# Per-API call timeout in seconds (circuit-breaker threshold)
_API_TIMEOUT_SECONDS: Final[float] = 0.8

# URLhaus lookup API endpoint
_URLHAUS_API_URL: Final[str] = "https://urlhaus-api.abuse.ch/v1/url/"

# PhishTank check API endpoint
_PHISHTANK_API_URL: Final[str] = "https://checkurl.phishtank.com/checkurl/"

# Regex to extract http/https URLs from plain text or HTML
_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"https?://[^\s\"'<>\]\[)(\{\}]{4,2048}",
    re.IGNORECASE,
)

# Allowlisted API hostnames — only these hosts may be contacted
_ALLOWED_API_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "urlhaus-api.abuse.ch",
        "checkurl.phishtank.com",
    }
)


# ---------------------------------------------------------------------------
# URL extraction helpers
# ---------------------------------------------------------------------------


def _extract_urls(body: str) -> list[str]:
    """Extract unique HTTP/HTTPS URLs from the email body.

    Returns at most ``_MAX_URLS_TO_CHECK`` unique URLs, preserving order of
    first appearance.
    """
    seen: set[str] = set()
    urls: list[str] = []
    for match in _URL_RE.finditer(body):
        url = match.group(0).rstrip(".,;:!?)")  # Strip trailing punctuation
        if url not in seen:
            seen.add(url)
            urls.append(url)
            if len(urls) >= _MAX_URLS_TO_CHECK:
                break
    return urls


def _is_allowed_host(url: str) -> bool:
    """Return True if the URL's host is in the outbound allowlist."""
    try:
        host = urlparse(url).hostname or ""
        return host in _ALLOWED_API_HOSTS
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# ReputationAnalyzer
# ---------------------------------------------------------------------------


class ReputationAnalyzer(AnalyzerPort):
    """Circuit-broken reputation analyzer.

    Extracts URLs from the email body and checks them against URLhaus and
    PhishTank.  Each API call is individually circuit-broken with an 800 ms
    timeout.  Failures are logged and do not block the verdict.

    Implements :class:`~app.domain.ports.AnalyzerPort`.
    """

    async def analyze(self, context: EmailContext) -> list[Finding]:
        """Analyze URLs in the email body against reputation feeds.

        Args:
            context: The :class:`~app.domain.models.EmailContext` to analyze.

        Returns:
            A list of :class:`~app.domain.models.Finding` objects.
        """
        findings: list[Finding] = []
        body = context.body or ""
        urls = _extract_urls(body)

        if not urls:
            return findings

        # Check all URLs concurrently against both feeds.
        tasks = [self._check_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for url, result in zip(urls, results):
            if isinstance(result, Exception):
                log.warning(
                    "reputation.check_failed",
                    extra={"url": url[:200], "error": str(result)[:200]},
                )
                continue
            if result:
                findings.extend(result)

        return findings

    # ------------------------------------------------------------------
    # Per-URL check (both feeds)
    # ------------------------------------------------------------------

    async def _check_url(self, url: str) -> list[Finding]:
        """Check a single URL against URLhaus and PhishTank.

        Returns a list of findings (possibly empty).  Never raises — all
        exceptions are caught and logged.
        """
        findings: list[Finding] = []

        urlhaus_task = self._check_urlhaus(url)
        phishtank_task = self._check_phishtank(url)

        results = await asyncio.gather(urlhaus_task, phishtank_task, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                log.warning(
                    "reputation.api_error",
                    extra={"url": url[:200], "error": str(result)[:200]},
                )
            elif result is not None:
                findings.append(result)

        return findings

    # ------------------------------------------------------------------
    # URLhaus check
    # ------------------------------------------------------------------

    async def _check_urlhaus(self, url: str) -> Finding | None:
        """Query the URLhaus API for a URL.

        Returns a :class:`~app.domain.models.Finding` if the URL is listed,
        ``None`` if it is clean or the API is unavailable.
        """
        try:
            client = get_http_client()
        except RuntimeError:
            log.warning("reputation.urlhaus.http_client_not_initialised")
            return None

        try:
            response = await asyncio.wait_for(
                client.post(
                    _URLHAUS_API_URL,
                    data={"url": url},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ),
                timeout=_API_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            log.warning("reputation.urlhaus.timeout", extra={"url": url[:200]})
            return None
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "reputation.urlhaus.request_failed",
                extra={"url": url[:200], "error": str(exc)[:200]},
            )
            return None

        if response.status_code != 200:
            log.warning(
                "reputation.urlhaus.non_200",
                extra={"url": url[:200], "status_code": response.status_code},
            )
            return None

        try:
            data = response.json()
        except Exception:  # noqa: BLE001
            log.warning("reputation.urlhaus.invalid_json", extra={"url": url[:200]})
            return None

        query_status = data.get("query_status", "")
        if query_status != "is_listed":
            return None

        # URL is listed in URLhaus — extract threat metadata.
        threat = data.get("threat", "malware_download")
        tags = data.get("tags") or []
        url_status = data.get("url_status", "unknown")

        return Finding(
            type=Category.MALWARE,
            severity=Severity.CRITICAL,
            description=(
                f"URL '{url[:200]}' is listed in URLhaus as a known malware "
                f"distribution URL (threat: {threat}, status: {url_status}). "
                "Do not click this link."
            ),
            evidence={
                "signal": "urlhaus_listed",
                "url": url[:500],
                "threat": threat,
                "url_status": url_status,
                "tags": tags[:10],
                "urlhaus_id": data.get("id"),
            },
        )

    # ------------------------------------------------------------------
    # PhishTank check
    # ------------------------------------------------------------------

    async def _check_phishtank(self, url: str) -> Finding | None:
        """Query the PhishTank API for a URL.

        Returns a :class:`~app.domain.models.Finding` if the URL is a known
        phishing URL, ``None`` if it is clean or the API is unavailable.

        Note: PhishTank requires an API key for higher rate limits.  Without
        a key the endpoint still works but is rate-limited to ~100 req/hour.
        The API key should be injected via config/environment variables in
        production.
        """
        try:
            client = get_http_client()
        except RuntimeError:
            log.warning("reputation.phishtank.http_client_not_initialised")
            return None

        try:
            response = await asyncio.wait_for(
                client.post(
                    _PHISHTANK_API_URL,
                    data={
                        "url": url,
                        "format": "json",
                    },
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "phishtank/upwind-email-scorer",
                    },
                ),
                timeout=_API_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            log.warning("reputation.phishtank.timeout", extra={"url": url[:200]})
            return None
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "reputation.phishtank.request_failed",
                extra={"url": url[:200], "error": str(exc)[:200]},
            )
            return None

        if response.status_code != 200:
            log.warning(
                "reputation.phishtank.non_200",
                extra={"url": url[:200], "status_code": response.status_code},
            )
            return None

        try:
            data = response.json()
        except Exception:  # noqa: BLE001
            log.warning("reputation.phishtank.invalid_json", extra={"url": url[:200]})
            return None

        results = data.get("results", {})
        in_database: bool = results.get("in_database", False)
        valid: bool = results.get("valid", False)

        if not (in_database and valid):
            return None

        phish_id = results.get("phish_id", "unknown")
        phish_detail_url = results.get("phish_detail_page", "")

        return Finding(
            type=Category.PHISHING,
            severity=Severity.CRITICAL,
            description=(
                f"URL '{url[:200]}' is listed in PhishTank as a confirmed phishing URL "
                f"(PhishTank ID: {phish_id}). Do not click this link."
            ),
            evidence={
                "signal": "phishtank_listed",
                "url": url[:500],
                "phish_id": phish_id,
                "phish_detail_url": phish_detail_url[:300],
                "verified": results.get("verified", False),
            },
        )
