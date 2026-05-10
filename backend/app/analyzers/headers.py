"""
backend/app/analyzers/headers.py
---------------------------------
Deterministic SPF, DKIM, and DMARC header analyzer.

This module is a **pure, side-effect-free** analyzer: given a dict of email
headers it returns a list of ``Finding`` objects. No I/O, no LLM, no network.

Design notes
============
* SPF, DKIM, and DMARC results are extracted from the ``Authentication-Results``
  header (RFC 7601) and from the individual ``Received-SPF`` / ``DKIM-Signature``
  headers as a fallback.
* We parse the *result* of authentication (pass/fail/softfail/none) rather than
  re-running the checks ourselves. The MTA has already done the DNS lookups; we
  trust its verdict and surface it as a structured finding.
* Each finding carries a ``severity`` so the score-fusion layer can weight them
  appropriately without knowing the details of header parsing.
* The analyzer is intentionally conservative: if a header is absent or
  unparseable, we emit a LOW-severity "missing" finding rather than assuming
  pass. Absence of evidence is not evidence of absence in email security.

Severity mapping
================
+------------------+----------+--------------------------------------------------+
| Condition        | Severity | Rationale                                        |
+==================+==========+==================================================+
| SPF fail/hardfail| HIGH     | Sender is explicitly not authorized              |
| SPF softfail     | MEDIUM   | Sender is probably not authorized                |
| SPF none/missing | LOW      | No policy published — common but worth noting    |
| DKIM fail        | HIGH     | Signature present but invalid — likely tampered  |
| DKIM none/missing| LOW      | No signature — common for forwarded mail         |
| DMARC fail       | HIGH     | Both SPF and DKIM alignment failed               |
| DMARC none       | MEDIUM   | No policy — domain owner has not opted in        |
+------------------+----------+--------------------------------------------------+
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AuthResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """A single deterministic finding produced by a header analyzer.

    Attributes
    ----------
    category:
        Machine-readable category string (e.g. ``"spf"``, ``"dkim"``,
        ``"dmarc"``).
    result:
        The parsed authentication result.
    severity:
        How serious this finding is for scoring purposes.
    detail:
        Human-readable explanation suitable for the SOC analyst UI.
    raw_header:
        The raw header value that produced this finding (for audit).
    """

    category: str
    result: AuthResult
    severity: Severity
    detail: str
    raw_header: str = ""


# ---------------------------------------------------------------------------
# Regex patterns for Authentication-Results header parsing (RFC 7601)
# ---------------------------------------------------------------------------

# Matches: spf=pass, spf=fail, spf=softfail, spf=none, etc.
_SPF_RESULT_RE = re.compile(
    r"\bspf=(?P<result>pass|fail|softfail|neutral|none|temperror|permerror)",
    re.IGNORECASE,
)

# Matches: dkim=pass, dkim=fail, dkim=none, etc.
_DKIM_RESULT_RE = re.compile(
    r"\bdkim=(?P<result>pass|fail|neutral|none|temperror|permerror)",
    re.IGNORECASE,
)

# Matches: dmarc=pass, dmarc=fail, dmarc=none, etc.
_DMARC_RESULT_RE = re.compile(
    r"\bdmarc=(?P<result>pass|fail|none|temperror|permerror)",
    re.IGNORECASE,
)

# Fallback: Received-SPF header (RFC 7208 §9.1)
_RECEIVED_SPF_RE = re.compile(
    r"^(?P<result>pass|fail|softfail|neutral|none|temperror|permerror)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_auth_result(value: str) -> AuthResult:
    """Normalise a raw result string to an ``AuthResult`` enum member."""
    try:
        return AuthResult(value.lower())
    except ValueError:
        return AuthResult.UNKNOWN


def _spf_severity(result: AuthResult) -> Severity:
    if result in (AuthResult.FAIL,):
        return Severity.HIGH
    if result in (AuthResult.SOFTFAIL,):
        return Severity.MEDIUM
    return Severity.LOW


def _dkim_severity(result: AuthResult) -> Severity:
    if result in (AuthResult.FAIL, AuthResult.PERMERROR):
        return Severity.HIGH
    return Severity.LOW


def _dmarc_severity(result: AuthResult) -> Severity:
    if result == AuthResult.FAIL:
        return Severity.HIGH
    if result == AuthResult.NONE:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_headers(headers: dict[str, str]) -> list[Finding]:
    """Parse email authentication headers and return a list of findings.

    Parameters
    ----------
    headers:
        A flat ``{header_name: header_value}`` dict.  Header names are
        compared case-insensitively.  If multiple ``Authentication-Results``
        headers are present, pass them joined with ``\\n``.

    Returns
    -------
    list[Finding]
        Zero or more findings.  An empty list means all checks passed
        cleanly (or no relevant headers were present).
    """
    # Normalise header names to lower-case for lookup.
    normalised: dict[str, str] = {k.lower(): v for k, v in headers.items()}

    findings: list[Finding] = []

    # ── Primary source: Authentication-Results (RFC 7601) ─────────────────
    auth_results_raw = normalised.get("authentication-results", "")

    findings.extend(_extract_spf(auth_results_raw, normalised))
    findings.extend(_extract_dkim(auth_results_raw, normalised))
    findings.extend(_extract_dmarc(auth_results_raw))

    return findings


def _extract_spf(
    auth_results: str,
    all_headers: dict[str, str],
) -> list[Finding]:
    """Extract SPF result from Authentication-Results or Received-SPF."""
    findings: list[Finding] = []

    # Try Authentication-Results first.
    match = _SPF_RESULT_RE.search(auth_results)
    if match:
        raw_result = match.group("result")
        result = _parse_auth_result(raw_result)
        severity = _spf_severity(result)
        detail = _spf_detail(result)
        findings.append(
            Finding(
                category="spf",
                result=result,
                severity=severity,
                detail=detail,
                raw_header=auth_results[:500],
            )
        )
        return findings

    # Fallback: Received-SPF header.
    received_spf = all_headers.get("received-spf", "").strip()
    if received_spf:
        match2 = _RECEIVED_SPF_RE.match(received_spf)
        if match2:
            result = _parse_auth_result(match2.group("result"))
            severity = _spf_severity(result)
            findings.append(
                Finding(
                    category="spf",
                    result=result,
                    severity=severity,
                    detail=_spf_detail(result),
                    raw_header=received_spf[:500],
                )
            )
            return findings

    # No SPF header found at all.
    findings.append(
        Finding(
            category="spf",
            result=AuthResult.NONE,
            severity=Severity.LOW,
            detail="No SPF result found in headers. Domain may not publish an SPF record.",
            raw_header="",
        )
    )
    return findings


def _extract_dkim(
    auth_results: str,
    all_headers: dict[str, str],
) -> list[Finding]:
    """Extract DKIM result from Authentication-Results."""
    findings: list[Finding] = []

    match = _DKIM_RESULT_RE.search(auth_results)
    if match:
        result = _parse_auth_result(match.group("result"))
        severity = _dkim_severity(result)
        findings.append(
            Finding(
                category="dkim",
                result=result,
                severity=severity,
                detail=_dkim_detail(result),
                raw_header=auth_results[:500],
            )
        )
        return findings

    # Check for presence of DKIM-Signature header (signature present but
    # no Authentication-Results means the MTA didn't verify it).
    if "dkim-signature" in all_headers:
        findings.append(
            Finding(
                category="dkim",
                result=AuthResult.NONE,
                severity=Severity.LOW,
                detail=(
                    "DKIM-Signature header present but no verification result found. "
                    "The receiving MTA may not have verified the signature."
                ),
                raw_header=all_headers["dkim-signature"][:200],
            )
        )
    else:
        findings.append(
            Finding(
                category="dkim",
                result=AuthResult.NONE,
                severity=Severity.LOW,
                detail="No DKIM signature found. Email was not signed by the sending domain.",
                raw_header="",
            )
        )
    return findings


def _extract_dmarc(auth_results: str) -> list[Finding]:
    """Extract DMARC result from Authentication-Results."""
    findings: list[Finding] = []

    match = _DMARC_RESULT_RE.search(auth_results)
    if match:
        result = _parse_auth_result(match.group("result"))
        severity = _dmarc_severity(result)
        findings.append(
            Finding(
                category="dmarc",
                result=result,
                severity=severity,
                detail=_dmarc_detail(result),
                raw_header=auth_results[:500],
            )
        )
        return findings

    # No DMARC result in Authentication-Results.
    findings.append(
        Finding(
            category="dmarc",
            result=AuthResult.NONE,
            severity=Severity.MEDIUM,
            detail=(
                "No DMARC result found. The sending domain may not publish a DMARC policy, "
                "or the receiving MTA did not evaluate it."
            ),
            raw_header="",
        )
    )
    return findings


# ---------------------------------------------------------------------------
# Human-readable detail strings
# ---------------------------------------------------------------------------


def _spf_detail(result: AuthResult) -> str:
    return {
        AuthResult.PASS: "SPF pass — sender IP is authorized by the domain's SPF record.",
        AuthResult.FAIL: "SPF fail — sender IP is explicitly NOT authorized. High phishing signal.",
        AuthResult.SOFTFAIL: "SPF softfail — sender IP is probably not authorized (~all policy).",
        AuthResult.NEUTRAL: "SPF neutral — domain owner makes no assertion about the sender.",
        AuthResult.NONE: "SPF none — no SPF record published for this domain.",
        AuthResult.TEMPERROR: "SPF temperror — DNS lookup failed transiently; result inconclusive.",
        AuthResult.PERMERROR: "SPF permerror — SPF record is malformed or has too many lookups.",
        AuthResult.UNKNOWN: "SPF result could not be parsed.",
    }.get(result, "SPF result unknown.")


def _dkim_detail(result: AuthResult) -> str:
    return {
        AuthResult.PASS: "DKIM pass — email body and headers are cryptographically intact.",
        AuthResult.FAIL: "DKIM fail — signature is present but INVALID. Email may have been tampered with.",
        AuthResult.NEUTRAL: "DKIM neutral — signature present but not conclusive.",
        AuthResult.NONE: "DKIM none — no DKIM signature found.",
        AuthResult.TEMPERROR: "DKIM temperror — key lookup failed transiently.",
        AuthResult.PERMERROR: "DKIM permerror — signature is malformed.",
        AuthResult.UNKNOWN: "DKIM result could not be parsed.",
    }.get(result, "DKIM result unknown.")


def _dmarc_detail(result: AuthResult) -> str:
    return {
        AuthResult.PASS: "DMARC pass — at least one of SPF/DKIM aligns with the From domain.",
        AuthResult.FAIL: "DMARC fail — neither SPF nor DKIM aligns with the From domain. Strong phishing signal.",
        AuthResult.NONE: "DMARC none — no DMARC policy published. Domain owner has not opted in.",
        AuthResult.TEMPERROR: "DMARC temperror — evaluation failed transiently.",
        AuthResult.PERMERROR: "DMARC permerror — DMARC record is malformed.",
        AuthResult.UNKNOWN: "DMARC result could not be parsed.",
    }.get(result, "DMARC result unknown.")
