"""
backend/app/analyzers/domains.py
---------------------------------
Deterministic domain-age and homograph/lookalike analyzer.

This module is a **pure, side-effect-free** analyzer for the parts of domain
analysis that do NOT require network I/O (i.e., no WHOIS lookups here — those
live in ``reputation.py`` which is circuit-broken). This module handles:

1. **Domain age scoring** — given a ``registered_date`` string (supplied by
   the caller from a pre-fetched WHOIS result), classify the domain as
   newly-registered, young, or established.

2. **Homograph / lookalike detection** — detect domains that visually
   impersonate well-known brands using:
   * IDN homograph attacks (e.g. ``pаypal.com`` with Cyrillic 'а')
   * Character substitution (e.g. ``paypa1.com``, ``rn`` → ``m``)
   * Subdomain abuse (e.g. ``paypal.com.evil.ru``)
   * Typosquatting (edit-distance ≤ 2 from a known brand domain)

Design notes
============
* No network calls. Domain age is passed in as a pre-computed value.
* The brand list is intentionally small and curated. False positives on
  legitimate domains are worse than false negatives here — the LLM layer
  will catch semantic impersonation that the regex misses.
* All findings are frozen dataclasses so they are safe to cache and hash.
* The ``analyze_domain`` function is the single public entry point; it
  returns a list of ``DomainFinding`` objects that the score-fusion layer
  can weight.

SSRF note
=========
This module never fetches URLs or resolves hostnames. Domain strings are
processed as text only. See ``reputation.py`` for the network-bound checks
(which are called with the domain as a query parameter to an allowlisted
reputation API, never by fetching the domain itself).
"""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime, timezone
from enum import Enum
from typing import Sequence

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums (shared with headers.py — in a real project these would live in
# domain/enums.py; duplicated here for module self-containment).
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DomainFinding:
    """A single deterministic finding produced by the domain analyzer.

    Attributes
    ----------
    category:
        Machine-readable category: ``"domain_age"``, ``"homograph"``,
        ``"lookalike"``, ``"subdomain_abuse"``, or ``"typosquatting"``.
    severity:
        How serious this finding is for scoring purposes.
    detail:
        Human-readable explanation for the SOC analyst UI.
    domain:
        The domain string that triggered this finding.
    matched_brand:
        The brand domain this finding is associated with (if any).
    """

    category: str
    severity: Severity
    detail: str
    domain: str
    matched_brand: str = ""


# ---------------------------------------------------------------------------
# Domain age thresholds
# ---------------------------------------------------------------------------

_AGE_HIGH_RISK_DAYS = 30      # < 30 days → HIGH
_AGE_MEDIUM_RISK_DAYS = 180   # 30–180 days → MEDIUM
# > 180 days → LOW (established)


# ---------------------------------------------------------------------------
# Brand lookalike list
# ---------------------------------------------------------------------------
# Keep this list small and high-precision. Each entry is the canonical
# registrable domain (eTLD+1) of a commonly impersonated brand.
# Extend via config in production; hardcoded here for the deterministic layer.

_BRAND_DOMAINS: frozenset[str] = frozenset(
    {
        "paypal.com",
        "microsoft.com",
        "google.com",
        "apple.com",
        "amazon.com",
        "netflix.com",
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "dropbox.com",
        "docusign.com",
        "chase.com",
        "wellsfargo.com",
        "bankofamerica.com",
        "citibank.com",
        "irs.gov",
        "fedex.com",
        "ups.com",
        "dhl.com",
        "usps.com",
    }
)

# ---------------------------------------------------------------------------
# Common character substitution map (visual lookalikes)
# ---------------------------------------------------------------------------
# Maps confusable characters to their ASCII equivalents for normalisation.
_CONFUSABLE_MAP: dict[str, str] = {
    # Digits that look like letters
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "8": "b",
    # Common bigram substitutions handled separately (rn→m)
    # Cyrillic lookalikes (common in IDN homograph attacks)
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "r",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0445": "x",  # Cyrillic х
    "\u0440": "r",  # Cyrillic р
    "\u0456": "i",  # Cyrillic і
    # Greek lookalikes
    "\u03bf": "o",  # Greek ο
    "\u03b1": "a",  # Greek α
    # Latin extended lookalikes
    "\u00e0": "a",
    "\u00e1": "a",
    "\u00e2": "a",
    "\u00e4": "a",
    "\u00e9": "e",
    "\u00ea": "e",
    "\u00eb": "e",
    "\u00ed": "i",
    "\u00f3": "o",
    "\u00fa": "u",
}

_BIGRAM_SUBS: list[tuple[str, str]] = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("li", "h"),
]

# ---------------------------------------------------------------------------
# Regex: extract registrable domain (eTLD+1) from a full domain string.
# This is a simplified extractor — production code should use ``tldextract``.
# ---------------------------------------------------------------------------
_DOMAIN_RE = re.compile(
    r"(?:^|\.)(?P<registrable>[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:[a-z]{2,}))$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_domain(
    domain: str,
    *,
    registered_date: date | datetime | str | None = None,
) -> list[DomainFinding]:
    """Analyze a domain for age and lookalike/homograph signals.

    Parameters
    ----------
    domain:
        The domain to analyze (e.g. ``"paypa1-billing.ru"``).  Should be
        the registrable domain (eTLD+1) where possible, but the function
        handles FQDNs and subdomains gracefully.
    registered_date:
        The domain's registration date, as a ``date``, ``datetime``, or
        ISO-8601 string (``"YYYY-MM-DD"``).  Pass ``None`` if unknown —
        the function will emit a LOW-severity "age unknown" finding.

    Returns
    -------
    list[DomainFinding]
        Zero or more findings.
    """
    domain = domain.strip().lower()
    findings: list[DomainFinding] = []

    findings.extend(_check_domain_age(domain, registered_date))
    findings.extend(_check_homograph(domain))
    findings.extend(_check_lookalike(domain))
    findings.extend(_check_subdomain_abuse(domain))

    return findings


# ---------------------------------------------------------------------------
# Domain age check
# ---------------------------------------------------------------------------


def _parse_registered_date(
    registered_date: date | datetime | str | None,
) -> date | None:
    if registered_date is None:
        return None
    if isinstance(registered_date, datetime):
        return registered_date.date()
    if isinstance(registered_date, date):
        return registered_date
    # Try ISO-8601 string.
    try:
        return date.fromisoformat(str(registered_date)[:10])
    except ValueError:
        log.warning("domains.unparseable_registered_date", extra={"value": str(registered_date)[:50]})
        return None


def _check_domain_age(
    domain: str,
    registered_date: date | datetime | str | None,
) -> list[DomainFinding]:
    parsed = _parse_registered_date(registered_date)

    if parsed is None:
        return [
            DomainFinding(
                category="domain_age",
                severity=Severity.LOW,
                detail=(
                    f"Domain age for '{domain}' is unknown (no WHOIS data available). "
                    "Treat with caution if other signals are present."
                ),
                domain=domain,
            )
        ]

    today = datetime.now(tz=timezone.utc).date()
    age_days = (today - parsed).days

    if age_days < 0:
        # Clock skew or bad data — treat as unknown.
        return [
            DomainFinding(
                category="domain_age",
                severity=Severity.LOW,
                detail=f"Domain '{domain}' has a future registration date ({parsed}). Data may be unreliable.",
                domain=domain,
            )
        ]

    if age_days < _AGE_HIGH_RISK_DAYS:
        return [
            DomainFinding(
                category="domain_age",
                severity=Severity.HIGH,
                detail=(
                    f"Domain '{domain}' was registered only {age_days} day(s) ago ({parsed}). "
                    "Newly-registered domains are a strong phishing signal."
                ),
                domain=domain,
            )
        ]

    if age_days < _AGE_MEDIUM_RISK_DAYS:
        return [
            DomainFinding(
                category="domain_age",
                severity=Severity.MEDIUM,
                detail=(
                    f"Domain '{domain}' was registered {age_days} days ago ({parsed}). "
                    "Young domains warrant additional scrutiny."
                ),
                domain=domain,
            )
        ]

    # Established domain — no finding needed (clean bill of health).
    return []


# ---------------------------------------------------------------------------
# Homograph detection (IDN / Unicode confusables)
# ---------------------------------------------------------------------------


def _normalise_for_comparison(domain: str) -> str:
    """Normalise a domain to ASCII by replacing confusable characters."""
    # Step 1: NFKC normalisation (decomposes ligatures, etc.)
    normalised = unicodedata.normalize("NFKC", domain)

    # Step 2: Replace known confusable characters.
    result = []
    for ch in normalised:
        result.append(_CONFUSABLE_MAP.get(ch, ch))
    text = "".join(result)

    # Step 3: Replace common bigram substitutions.
    for bigram, replacement in _BIGRAM_SUBS:
        text = text.replace(bigram, replacement)

    return text


def _check_homograph(domain: str) -> list[DomainFinding]:
    """Detect IDN homograph attacks (non-ASCII chars that look like ASCII)."""
    findings: list[DomainFinding] = []

    # Check if the domain contains non-ASCII characters.
    try:
        domain.encode("ascii")
        return []  # Pure ASCII — no homograph risk from this check.
    except UnicodeEncodeError:
        pass

    # The domain contains non-ASCII characters. Normalise and check against
    # brand list.
    normalised = _normalise_for_comparison(domain)
    registrable = _extract_registrable(normalised)

    for brand in _BRAND_DOMAINS:
        if registrable == brand:
            findings.append(
                DomainFinding(
                    category="homograph",
                    severity=Severity.HIGH,
                    detail=(
                        f"Domain '{domain}' contains non-ASCII characters that visually "
                        f"resemble '{brand}'. This is a classic IDN homograph attack."
                    ),
                    domain=domain,
                    matched_brand=brand,
                )
            )
            break

    if not findings and any(ord(c) > 127 for c in domain):
        findings.append(
            DomainFinding(
                category="homograph",
                severity=Severity.MEDIUM,
                detail=(
                    f"Domain '{domain}' contains non-ASCII (Unicode) characters. "
                    "This may indicate an IDN homograph attack against an unlisted brand."
                ),
                domain=domain,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Lookalike / typosquatting detection
# ---------------------------------------------------------------------------


def _extract_registrable(domain: str) -> str:
    """Extract the registrable domain (eTLD+1) from a full domain string.

    This is a simplified implementation. Production code should use
    ``tldextract`` for accurate public-suffix handling.
    """
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _check_lookalike(domain: str) -> list[DomainFinding]:
    """Detect character-substitution lookalikes and typosquatting."""
    findings: list[DomainFinding] = []

    # Normalise the domain for comparison.
    normalised = _normalise_for_comparison(domain)
    registrable = _extract_registrable(normalised)

    for brand in _BRAND_DOMAINS:
        if registrable == brand:
            # Exact match after normalisation — already caught by homograph
            # check if the original had non-ASCII chars; skip here.
            continue

        dist = _levenshtein(registrable, brand)
        if dist == 0:
            continue  # Exact match — legitimate domain.

        if dist <= 2:
            findings.append(
                DomainFinding(
                    category="typosquatting",
                    severity=Severity.HIGH if dist == 1 else Severity.MEDIUM,
                    detail=(
                        f"Domain '{domain}' is {dist} edit(s) away from brand domain '{brand}'. "
                        "This is a strong typosquatting signal."
                    ),
                    domain=domain,
                    matched_brand=brand,
                )
            )

    return findings


def _check_subdomain_abuse(domain: str) -> list[DomainFinding]:
    """Detect brand names used as subdomains of unrelated registrable domains.

    Example: ``paypal.com.evil-phish.ru`` — the registrable domain is
    ``evil-phish.ru`` but ``paypal.com`` appears as a subdomain prefix,
    which tricks users who only glance at the beginning of the URL.
    """
    findings: list[DomainFinding] = []

    registrable = _extract_registrable(domain)

    # Check if any brand domain appears as a prefix/subdomain component.
    for brand in _BRAND_DOMAINS:
        brand_without_tld = brand.split(".")[0]  # e.g. "paypal" from "paypal.com"

        # The brand's registrable domain appears in the subdomain portion.
        if domain.startswith(brand + ".") and registrable != brand:
            findings.append(
                DomainFinding(
                    category="subdomain_abuse",
                    severity=Severity.HIGH,
                    detail=(
                        f"Domain '{domain}' uses '{brand}' as a subdomain prefix. "
                        f"The actual registrable domain is '{registrable}'. "
                        "This is a common phishing technique to deceive users."
                    ),
                    domain=domain,
                    matched_brand=brand,
                )
            )
            break

        # The brand name (without TLD) appears as a subdomain component.
        if (
            f".{brand_without_tld}." in f".{domain}."
            and registrable != brand
            and brand_without_tld in domain
            and not domain.endswith(f".{brand}")
        ):
            # Only flag if the registrable domain is clearly different.
            if registrable not in (brand, f"{brand_without_tld}.com"):
                findings.append(
                    DomainFinding(
                        category="subdomain_abuse",
                        severity=Severity.MEDIUM,
                        detail=(
                            f"Domain '{domain}' contains brand name '{brand_without_tld}' "
                            f"as a subdomain component. Registrable domain is '{registrable}'. "
                            "Verify this is a legitimate service."
                        ),
                        domain=domain,
                        matched_brand=brand,
                    )
                )
                break

    return findings
