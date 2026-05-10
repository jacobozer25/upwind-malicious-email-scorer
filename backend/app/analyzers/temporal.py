"""
backend/app/analyzers/temporal.py
-----------------------------------
Deterministic temporal analyzer for the malicious email scorer.

This analyzer inspects the ``Date`` header of an email for time-based
anomalies that correlate with phishing and social-engineering campaigns:

1. **Off-hours sending** — emails sent between 02:00 and 05:00 UTC (or in the
   sender's apparent timezone if parseable) are flagged.  Legitimate business
   email is rarely sent in the early hours; attackers often schedule sends
   during low-vigilance windows.

2. **Future-dated emails** — a ``Date`` header more than 15 minutes in the
   future indicates clock skew or deliberate header manipulation.

3. **Very old / stale emails** — a ``Date`` header more than 30 days in the
   past may indicate a replay attack or header forgery.

4. **First-contact hook** (placeholder) — a stub for future integration with
   a sender-history data source.  When wired, this will flag emails from
   senders the recipient has never interacted with.

Design notes
============
* No network calls — all checks are purely based on the ``Date`` header value.
* The ``Date`` header is parsed with :mod:`email.utils` (stdlib) which handles
  the full RFC 2822 date format including timezone offsets.
* All findings use ``Category.SUSPICIOUS_CONTENT`` with appropriate severity.
* Implements :class:`~app.domain.ports.AnalyzerPort`.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Final

from app.domain.enums import Category, Severity
from app.domain.models import EmailContext, Finding
from app.domain.ports import AnalyzerPort

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Off-hours window (UTC): 02:00 – 05:00
_OFF_HOURS_START_UTC: Final[int] = 2   # inclusive
_OFF_HOURS_END_UTC: Final[int] = 5     # exclusive (i.e., 02:00 ≤ hour < 05:00)

# Maximum allowed clock skew into the future (minutes)
_MAX_FUTURE_SKEW_MINUTES: Final[int] = 15

# Maximum age before an email is considered suspiciously stale (days)
_MAX_STALE_DAYS: Final[int] = 30

# Header name for the send timestamp
_DATE_HEADER: Final[str] = "Date"


# ---------------------------------------------------------------------------
# TemporalAnalyzer
# ---------------------------------------------------------------------------


class TemporalAnalyzer(AnalyzerPort):
    """Deterministic temporal analyzer.

    Inspects the ``Date`` header for off-hours sending, future-dating, and
    staleness.  Includes a placeholder hook for first-contact detection.

    Implements :class:`~app.domain.ports.AnalyzerPort`.
    """

    async def analyze(self, context: EmailContext) -> list[Finding]:
        """Analyze the email's temporal metadata for suspicious signals.

        Args:
            context: The :class:`~app.domain.models.EmailContext` to analyze.

        Returns:
            A list of :class:`~app.domain.models.Finding` objects.
        """
        findings: list[Finding] = []

        send_time = self._parse_date_header(context)
        if send_time is None:
            findings.append(self._missing_date_finding())
            # Without a parseable date we cannot run the time-based checks.
            findings.extend(self._check_first_contact(context))
            return findings

        # Normalise to UTC for all comparisons.
        send_time_utc = send_time.astimezone(timezone.utc)
        now_utc = datetime.now(tz=timezone.utc)

        findings.extend(self._check_off_hours(send_time_utc, send_time))
        findings.extend(self._check_future_date(send_time_utc, now_utc))
        findings.extend(self._check_stale_date(send_time_utc, now_utc))
        findings.extend(self._check_first_contact(context))

        return findings

    # ------------------------------------------------------------------
    # Date header parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_date_header(context: EmailContext) -> datetime | None:
        """Parse the ``Date`` header from the email context.

        Returns a timezone-aware :class:`datetime` or ``None`` if the header
        is absent or unparseable.
        """
        # Headers dict may use different capitalisation.
        date_value: str | None = None
        for key, value in context.headers.items():
            if key.strip().lower() == "date":
                date_value = value
                break

        if not date_value:
            return None

        try:
            dt = parsedate_to_datetime(date_value)
            # Ensure timezone-aware; assume UTC if naive.
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:  # noqa: BLE001
            log.debug(
                "temporal.unparseable_date_header",
                extra={"date_value": date_value[:100]},
            )
            return None

    # ------------------------------------------------------------------
    # Off-hours check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_off_hours(
        send_time_utc: datetime, send_time_original: datetime
    ) -> list[Finding]:
        """Flag emails sent during the off-hours window (02:00–05:00 UTC)."""
        hour_utc = send_time_utc.hour

        if not (_OFF_HOURS_START_UTC <= hour_utc < _OFF_HOURS_END_UTC):
            return []

        # Determine the original timezone offset for the description.
        tz_info = send_time_original.tzinfo
        tz_label = (
            str(tz_info) if tz_info else "UTC"
        )

        return [
            Finding(
                type=Category.SUSPICIOUS_CONTENT,
                severity=Severity.MEDIUM,
                description=(
                    f"Email was sent at {send_time_utc.strftime('%H:%M')} UTC "
                    f"({send_time_original.strftime('%H:%M')} {tz_label}), "
                    f"which falls within the off-hours window "
                    f"({_OFF_HOURS_START_UTC:02d}:00–{_OFF_HOURS_END_UTC:02d}:00 UTC). "
                    "Phishing campaigns are often scheduled during low-vigilance hours."
                ),
                evidence={
                    "signal": "off_hours_send",
                    "send_time_utc": send_time_utc.isoformat(),
                    "send_time_local": send_time_original.isoformat(),
                    "hour_utc": hour_utc,
                    "off_hours_window": f"{_OFF_HOURS_START_UTC:02d}:00–{_OFF_HOURS_END_UTC:02d}:00 UTC",
                },
            )
        ]

    # ------------------------------------------------------------------
    # Future-date check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_future_date(
        send_time_utc: datetime, now_utc: datetime
    ) -> list[Finding]:
        """Flag emails whose ``Date`` header is in the future."""
        skew = send_time_utc - now_utc
        if skew <= timedelta(minutes=_MAX_FUTURE_SKEW_MINUTES):
            return []

        return [
            Finding(
                type=Category.SUSPICIOUS_CONTENT,
                severity=Severity.HIGH,
                description=(
                    f"Email ``Date`` header is {skew.total_seconds() / 60:.0f} minutes "
                    "in the future. Future-dated emails indicate clock manipulation or "
                    "deliberate header forgery."
                ),
                evidence={
                    "signal": "future_dated_email",
                    "send_time_utc": send_time_utc.isoformat(),
                    "current_time_utc": now_utc.isoformat(),
                    "skew_minutes": round(skew.total_seconds() / 60, 1),
                },
            )
        ]

    # ------------------------------------------------------------------
    # Stale-date check
    # ------------------------------------------------------------------

    @staticmethod
    def _check_stale_date(
        send_time_utc: datetime, now_utc: datetime
    ) -> list[Finding]:
        """Flag emails whose ``Date`` header is suspiciously old."""
        age = now_utc - send_time_utc
        if age <= timedelta(days=_MAX_STALE_DAYS):
            return []

        return [
            Finding(
                type=Category.SUSPICIOUS_CONTENT,
                severity=Severity.MEDIUM,
                description=(
                    f"Email ``Date`` header is {age.days} days old "
                    f"({send_time_utc.strftime('%Y-%m-%d')}). "
                    "Stale timestamps may indicate a replay attack or header forgery."
                ),
                evidence={
                    "signal": "stale_email",
                    "send_time_utc": send_time_utc.isoformat(),
                    "current_time_utc": now_utc.isoformat(),
                    "age_days": age.days,
                },
            )
        ]

    # ------------------------------------------------------------------
    # Missing Date header
    # ------------------------------------------------------------------

    @staticmethod
    def _missing_date_finding() -> Finding:
        """Return a finding for a missing or unparseable ``Date`` header."""
        return Finding(
            type=Category.SUSPICIOUS_CONTENT,
            severity=Severity.LOW,
            description=(
                "The email is missing a valid ``Date`` header or the header could not "
                "be parsed. Legitimate email servers always set a well-formed Date header."
            ),
            evidence={"signal": "missing_or_invalid_date_header"},
        )

    # ------------------------------------------------------------------
    # First-contact hook (placeholder)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_first_contact(context: EmailContext) -> list[Finding]:
        """Placeholder hook for first-contact / sender-history detection.

        This method is intentionally a no-op in v1.  When a sender-history
        data source is wired (see plan.md backlog item #61), this method
        should:

        1. Look up ``context.sender`` in the recipient's interaction history.
        2. If no prior interaction exists, return a MEDIUM-severity finding
           with ``signal = "first_contact_sender"``.
        3. If the sender domain impersonates a known internal domain, escalate
           to HIGH severity.

        Returns:
            An empty list (no-op in v1).
        """
        # TODO (backlog #61): Wire sender-history data source.
        # Example implementation once data is available:
        #
        #   history = await sender_history_service.get(context.sender)
        #   if not history.has_prior_contact:
        #       return [Finding(
        #           type=Category.SUSPICIOUS_CONTENT,
        #           severity=Severity.MEDIUM,
        #           description=f"First contact from sender '{context.sender}'.",
        #           evidence={"signal": "first_contact_sender", "sender": context.sender},
        #       )]
        #
        return []
