"""
backend/app/analyzers/content.py
----------------------------------
Deterministic content analyzer for the malicious email scorer.

This analyzer inspects the email body (plain-text or HTML) for three classes
of suspicious content signals:

1. **Urgency / Scarcity cues** — keywords and phrases that create artificial
   time pressure or threaten account suspension to coerce the recipient into
   acting without thinking (a classic social-engineering technique).

2. **Tracking pixels** — 1×1 ``<img>`` tags or well-known tracking URL
   patterns embedded in HTML bodies.  These are used by phishers to confirm
   that a target opened the email (beacon / read-receipt abuse).

3. **Hidden text** — zero-font-size spans, ``display:none`` / ``visibility:
   hidden`` CSS, or text whose color matches the background.  Hidden text is
   used to poison spam filters or to smuggle prompt-injection payloads past
   the deterministic layer.

Design notes
============
* No network calls — all checks are purely textual / regex-based.
* All findings use ``Category.SUSPICIOUS_CONTENT`` from the domain enums.
* Severity is calibrated conservatively: urgency cues alone are LOW/MEDIUM
  (they appear in legitimate marketing too); tracking pixels are MEDIUM;
  hidden text is HIGH (almost never legitimate in transactional email).
* The analyzer implements :class:`~app.domain.ports.AnalyzerPort` so it can
  be dropped into the orchestrator alongside the other deterministic analyzers.
"""
from __future__ import annotations

import re
from typing import Final

from app.domain.enums import Category, Severity
from app.domain.models import EmailContext, Finding
from app.domain.ports import AnalyzerPort

# ---------------------------------------------------------------------------
# Urgency / scarcity keyword patterns
# ---------------------------------------------------------------------------
# Each tuple is (compiled_regex, human_label, Severity).
# Patterns are case-insensitive.  We use word-boundary anchors where possible
# to reduce false positives on substrings.

_URGENCY_PATTERNS: Final[list[tuple[re.Pattern[str], str, Severity]]] = [
    # Critical / account-suspension language
    (
        re.compile(
            r"\b(account\s+(locked|suspended|disabled|terminated|blocked|compromised))\b",
            re.IGNORECASE,
        ),
        "account suspension language",
        Severity.HIGH,
    ),
    (
        re.compile(
            r"\b(verify\s+your\s+(account|identity|email|information))\b",
            re.IGNORECASE,
        ),
        "account verification demand",
        Severity.MEDIUM,
    ),
    (
        re.compile(
            r"\b(unusual\s+(sign[\-\s]?in|activity|login|access))\b",
            re.IGNORECASE,
        ),
        "unusual activity claim",
        Severity.MEDIUM,
    ),
    # Immediate-action language
    (
        re.compile(r"\bimmediately\b", re.IGNORECASE),
        "immediate-action demand",
        Severity.LOW,
    ),
    (
        re.compile(
            r"\b(action\s+required|response\s+required|urgent\s+action)\b",
            re.IGNORECASE,
        ),
        "action-required demand",
        Severity.MEDIUM,
    ),
    (
        re.compile(
            r"\b(act\s+now|respond\s+now|reply\s+immediately|click\s+now)\b",
            re.IGNORECASE,
        ),
        "act-now demand",
        Severity.MEDIUM,
    ),
    # Time-pressure / expiry language
    (
        re.compile(
            r"\b(expires?\s+(in|within)\s+\d+\s+(hour|minute|day)s?|"
            r"limited\s+time|offer\s+expires?|deadline)\b",
            re.IGNORECASE,
        ),
        "time-pressure / expiry language",
        Severity.LOW,
    ),
    (
        re.compile(
            r"\b(within\s+\d+\s+(hour|minute)s?|in\s+the\s+next\s+\d+\s+(hour|minute)s?)\b",
            re.IGNORECASE,
        ),
        "short-window time pressure",
        Severity.MEDIUM,
    ),
    # Threat / consequence language
    (
        re.compile(
            r"\b(your\s+account\s+will\s+be\s+(deleted|closed|deactivated|removed|terminated))\b",
            re.IGNORECASE,
        ),
        "account-deletion threat",
        Severity.HIGH,
    ),
    (
        re.compile(
            r"\b(failure\s+to\s+(comply|respond|verify|confirm|update))\b",
            re.IGNORECASE,
        ),
        "failure-to-comply threat",
        Severity.MEDIUM,
    ),
    (
        re.compile(
            r"\b(legal\s+(action|proceedings?|consequences?)|law\s+enforcement)\b",
            re.IGNORECASE,
        ),
        "legal-threat language",
        Severity.HIGH,
    ),
    # Credential / payment harvesting cues
    (
        re.compile(
            r"\b(confirm\s+(your\s+)?(password|credit\s+card|bank\s+(account|details)|"
            r"social\s+security|ssn|billing\s+information))\b",
            re.IGNORECASE,
        ),
        "credential/payment harvesting cue",
        Severity.HIGH,
    ),
    (
        re.compile(
            r"\b(update\s+(your\s+)?(payment|billing|credit\s+card|bank)\s+(info|information|details))\b",
            re.IGNORECASE,
        ),
        "payment-update demand",
        Severity.HIGH,
    ),
]

# ---------------------------------------------------------------------------
# Tracking pixel patterns
# ---------------------------------------------------------------------------
# 1×1 img tags (width/height attributes or inline style).
_TRACKING_PIXEL_IMG_RE: Final[re.Pattern[str]] = re.compile(
    r"<img\b[^>]*\b(?:width\s*=\s*[\"']?\s*1\s*[\"']?[^>]*height\s*=\s*[\"']?\s*1\s*[\"']?|"
    r"height\s*=\s*[\"']?\s*1\s*[\"']?[^>]*width\s*=\s*[\"']?\s*1\s*[\"']?)[^>]*>",
    re.IGNORECASE | re.DOTALL,
)

# Known tracking / analytics URL patterns embedded in img src attributes.
_TRACKING_URL_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"https?://[^\"'>\s]*\b(track|pixel|beacon|open|click|analytics|trk|t\.co)\b[^\"'>\s]*", re.IGNORECASE),
    re.compile(r"https?://[^\"'>\s]*/[a-zA-Z0-9_\-]{20,}/[^\"'>\s]*\.(gif|png|jpg)\b", re.IGNORECASE),
    # Mailchimp / Sendgrid / common ESP tracking pixels
    re.compile(r"https?://[^\"'>\s]*\.(list-manage\.com|sendgrid\.net|mailgun\.org|mandrillapp\.com)[^\"'>\s]*/track", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Hidden text patterns
# ---------------------------------------------------------------------------
# Zero-font-size spans.
_ZERO_FONT_RE: Final[re.Pattern[str]] = re.compile(
    r"font-size\s*:\s*0\s*(px|pt|em|rem|%)?",
    re.IGNORECASE,
)

# display:none or visibility:hidden inline styles.
_DISPLAY_NONE_RE: Final[re.Pattern[str]] = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden)",
    re.IGNORECASE,
)

# Color matching background (white-on-white / black-on-black).
# Detects patterns like color:#ffffff;background:#ffffff or color:white;background:white.
_COLOR_MATCH_RE: Final[re.Pattern[str]] = re.compile(
    r"color\s*:\s*(?P<fg>#(?:fff(?:fff)?|000(?:000)?)|white|black)\b[^;\"']{0,80}"
    r"background(?:-color)?\s*:\s*(?P=fg)",
    re.IGNORECASE,
)

# HTML comment injection (sometimes used to hide text from spam filters).
_COMMENT_INJECTION_RE: Final[re.Pattern[str]] = re.compile(
    r"<!--(?!.*?-->).{200,}",  # Unclosed or very long HTML comment
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# ContentAnalyzer
# ---------------------------------------------------------------------------


class ContentAnalyzer(AnalyzerPort):
    """Deterministic content analyzer for urgency cues, tracking pixels, and
    hidden text.

    Implements :class:`~app.domain.ports.AnalyzerPort`.
    """

    async def analyze(self, context: EmailContext) -> list[Finding]:
        """Analyze the email body for suspicious content signals.

        Args:
            context: The :class:`~app.domain.models.EmailContext` to analyze.

        Returns:
            A list of :class:`~app.domain.models.Finding` objects, one per
            distinct signal detected.  Returns an empty list for clean emails.
        """
        findings: list[Finding] = []
        body = context.body or ""

        findings.extend(self._check_urgency(body))
        findings.extend(self._check_tracking_pixels(body))
        findings.extend(self._check_hidden_text(body))

        return findings

    # ------------------------------------------------------------------
    # Urgency / scarcity checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_urgency(body: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_labels: set[str] = set()

        for pattern, label, severity in _URGENCY_PATTERNS:
            if label in seen_labels:
                continue
            match = pattern.search(body)
            if match:
                seen_labels.add(label)
                findings.append(
                    Finding(
                        type=Category.SUSPICIOUS_CONTENT,
                        severity=severity,
                        description=(
                            f"Urgency/scarcity cue detected: {label}. "
                            f"Matched text: \"{match.group(0)[:120]}\""
                        ),
                        evidence={
                            "signal": "urgency_cue",
                            "label": label,
                            "matched_text": match.group(0)[:200],
                            "match_start": match.start(),
                        },
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Tracking pixel checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_tracking_pixels(body: str) -> list[Finding]:
        findings: list[Finding] = []

        # 1×1 image tag
        match = _TRACKING_PIXEL_IMG_RE.search(body)
        if match:
            findings.append(
                Finding(
                    type=Category.SUSPICIOUS_CONTENT,
                    severity=Severity.MEDIUM,
                    description=(
                        "Tracking pixel detected: a 1×1 pixel <img> tag was found in the "
                        "email body. This is commonly used to confirm email opens (read receipts)."
                    ),
                    evidence={
                        "signal": "tracking_pixel_1x1_img",
                        "matched_tag": match.group(0)[:300],
                        "match_start": match.start(),
                    },
                )
            )

        # Known tracking URL patterns
        for pattern in _TRACKING_URL_PATTERNS:
            url_match = pattern.search(body)
            if url_match:
                findings.append(
                    Finding(
                        type=Category.SUSPICIOUS_CONTENT,
                        severity=Severity.MEDIUM,
                        description=(
                            "Tracking/beacon URL pattern detected in the email body. "
                            f"Matched: \"{url_match.group(0)[:120]}\""
                        ),
                        evidence={
                            "signal": "tracking_url_pattern",
                            "matched_url": url_match.group(0)[:300],
                            "match_start": url_match.start(),
                        },
                    )
                )
                break  # One finding per category is sufficient.

        return findings

    # ------------------------------------------------------------------
    # Hidden text checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_hidden_text(body: str) -> list[Finding]:
        findings: list[Finding] = []

        # Zero-font-size
        match = _ZERO_FONT_RE.search(body)
        if match:
            findings.append(
                Finding(
                    type=Category.SUSPICIOUS_CONTENT,
                    severity=Severity.HIGH,
                    description=(
                        "Hidden text detected: zero font-size CSS property found in the email "
                        "body. This technique is used to hide text from human readers while "
                        "keeping it visible to parsers (spam filter evasion or prompt injection)."
                    ),
                    evidence={
                        "signal": "hidden_text_zero_font",
                        "matched_css": match.group(0)[:200],
                        "match_start": match.start(),
                    },
                )
            )

        # display:none / visibility:hidden
        match = _DISPLAY_NONE_RE.search(body)
        if match:
            findings.append(
                Finding(
                    type=Category.SUSPICIOUS_CONTENT,
                    severity=Severity.HIGH,
                    description=(
                        "Hidden text detected: CSS 'display:none' or 'visibility:hidden' found "
                        "in the email body. Hidden elements may contain spam-filter evasion text "
                        "or prompt-injection payloads."
                    ),
                    evidence={
                        "signal": "hidden_text_display_none",
                        "matched_css": match.group(0)[:200],
                        "match_start": match.start(),
                    },
                )
            )

        # Color-matching (white-on-white / black-on-black)
        match = _COLOR_MATCH_RE.search(body)
        if match:
            findings.append(
                Finding(
                    type=Category.SUSPICIOUS_CONTENT,
                    severity=Severity.HIGH,
                    description=(
                        "Hidden text detected: foreground color matches background color in the "
                        "email body. This renders text invisible to human readers while keeping "
                        "it parseable by machines."
                    ),
                    evidence={
                        "signal": "hidden_text_color_match",
                        "matched_css": match.group(0)[:200],
                        "match_start": match.start(),
                    },
                )
            )

        # Very long / unclosed HTML comment
        match = _COMMENT_INJECTION_RE.search(body)
        if match:
            findings.append(
                Finding(
                    type=Category.SUSPICIOUS_CONTENT,
                    severity=Severity.MEDIUM,
                    description=(
                        "Suspicious HTML comment detected: an unusually long or unclosed HTML "
                        "comment was found. This may be used to hide text from spam filters or "
                        "to inject content into downstream parsers."
                    ),
                    evidence={
                        "signal": "hidden_text_html_comment",
                        "snippet": match.group(0)[:200],
                        "match_start": match.start(),
                    },
                )
            )

        return findings
