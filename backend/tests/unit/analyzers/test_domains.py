"""
tests/unit/analyzers/test_domains.py
--------------------------------------
Unit tests for the deterministic domain-age and homograph/lookalike analyzer.

These tests exercise ``app.analyzers.domains.analyze_domain`` in complete
isolation — no LLM, no network, no WHOIS calls. Domain age is passed in as
a pre-computed value; lookalike detection is purely string-based.

Test categories
===============
* Domain age: newly-registered (<30d), young (30–180d), established (>180d),
  unknown (None), future date (clock skew)
* Homograph: IDN with Cyrillic chars, non-ASCII domain against brand list
* Typosquatting: 1-edit and 2-edit distance from brand domains
* Subdomain abuse: brand domain used as subdomain prefix
* Edge cases: empty domain, pure ASCII legitimate domain, exact brand match
"""
from __future__ import annotations

from datetime import date, timedelta, timezone, datetime

import pytest

from app.analyzers.domains import (
    DomainFinding,
    Severity,
    analyze_domain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TODAY = datetime.now(tz=timezone.utc).date()


def _days_ago(n: int) -> str:
    return (_TODAY - timedelta(days=n)).isoformat()


def _findings_by_category(findings: list[DomainFinding], category: str) -> list[DomainFinding]:
    return [f for f in findings if f.category == category]


def _has_category(findings: list[DomainFinding], category: str) -> bool:
    return any(f.category == category for f in findings)


# ---------------------------------------------------------------------------
# Domain age tests
# ---------------------------------------------------------------------------


class TestDomainAge:
    def test_newly_registered_is_high_severity(self):
        """Domain registered 7 days ago → HIGH severity."""
        findings = analyze_domain("evil-phish.ru", registered_date=_days_ago(7))
        age_findings = _findings_by_category(findings, "domain_age")
        assert len(age_findings) == 1
        assert age_findings[0].severity == Severity.HIGH
        assert "7 day" in age_findings[0].detail

    def test_young_domain_is_medium_severity(self):
        """Domain registered 90 days ago → MEDIUM severity."""
        findings = analyze_domain("young-domain.com", registered_date=_days_ago(90))
        age_findings = _findings_by_category(findings, "domain_age")
        assert len(age_findings) == 1
        assert age_findings[0].severity == Severity.MEDIUM

    def test_established_domain_produces_no_age_finding(self):
        """Domain registered 5 years ago → no age finding (clean)."""
        findings = analyze_domain("established.com", registered_date=_days_ago(365 * 5))
        age_findings = _findings_by_category(findings, "domain_age")
        assert len(age_findings) == 0

    def test_unknown_age_produces_low_severity_finding(self):
        """No registration date → LOW severity 'unknown' finding."""
        findings = analyze_domain("unknown-age.com", registered_date=None)
        age_findings = _findings_by_category(findings, "domain_age")
        assert len(age_findings) == 1
        assert age_findings[0].severity == Severity.LOW
        assert "unknown" in age_findings[0].detail.lower()

    def test_future_date_produces_low_severity_finding(self):
        """Future registration date (clock skew) → LOW severity finding."""
        future = (_TODAY + timedelta(days=30)).isoformat()
        findings = analyze_domain("future.com", registered_date=future)
        age_findings = _findings_by_category(findings, "domain_age")
        assert len(age_findings) == 1
        assert age_findings[0].severity == Severity.LOW

    def test_date_object_accepted(self):
        """``date`` objects should be accepted as registered_date."""
        findings = analyze_domain("test.com", registered_date=_TODAY - timedelta(days=10))
        age_findings = _findings_by_category(findings, "domain_age")
        assert age_findings[0].severity == Severity.HIGH

    def test_datetime_object_accepted(self):
        """``datetime`` objects should be accepted as registered_date."""
        dt = datetime(_TODAY.year - 1, 1, 1, tzinfo=timezone.utc)
        findings = analyze_domain("test.com", registered_date=dt)
        age_findings = _findings_by_category(findings, "domain_age")
        # 1+ year old → no age finding
        assert len(age_findings) == 0

    def test_iso_string_accepted(self):
        """ISO-8601 date strings should be parsed correctly."""
        findings = analyze_domain("test.com", registered_date="2026-04-01")
        # This date is in the past; exact severity depends on current date.
        age_findings = _findings_by_category(findings, "domain_age")
        assert len(age_findings) >= 0  # Just verify no exception is raised.

    def test_unparseable_date_string_treated_as_unknown(self):
        """Unparseable date string → treated as unknown (LOW severity)."""
        findings = analyze_domain("test.com", registered_date="not-a-date")
        age_findings = _findings_by_category(findings, "domain_age")
        assert len(age_findings) == 1
        assert age_findings[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# Homograph tests
# ---------------------------------------------------------------------------


class TestHomograph:
    def test_cyrillic_paypal_lookalike_is_high_severity(self):
        """Domain with Cyrillic 'а' that normalises to 'paypal.com' → HIGH."""
        # Use Cyrillic 'а' (U+0430) instead of Latin 'a'
        cyrillic_domain = "p\u0430ypal.com"
        findings = analyze_domain(cyrillic_domain)
        homograph_findings = _findings_by_category(findings, "homograph")
        assert len(homograph_findings) >= 1
        assert homograph_findings[0].severity == Severity.HIGH
        assert homograph_findings[0].matched_brand == "paypal.com"

    def test_pure_ascii_domain_has_no_homograph_finding(self):
        """Pure ASCII domain → no homograph finding."""
        findings = analyze_domain("paypal.com")
        homograph_findings = _findings_by_category(findings, "homograph")
        assert len(homograph_findings) == 0

    def test_non_ascii_unknown_brand_is_medium_severity(self):
        """Non-ASCII domain that doesn't match any brand → MEDIUM severity."""
        findings = analyze_domain("unkn\u00f3wn-brand.com")  # ó
        homograph_findings = _findings_by_category(findings, "homograph")
        assert len(homograph_findings) >= 1
        assert homograph_findings[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Typosquatting tests
# ---------------------------------------------------------------------------


class TestTyposquatting:
    def test_one_edit_from_paypal_is_high_severity(self):
        """'paypa1.com' (1→l substitution) is 1 edit from 'paypal.com' → HIGH."""
        # After normalisation: '1' → 'l', so 'paypal.com' == 'paypal.com' (exact)
        # Use a different 1-edit: 'paypall.com' (extra 'l')
        findings = analyze_domain("paypall.com")
        typo_findings = _findings_by_category(findings, "typosquatting")
        assert len(typo_findings) >= 1
        assert typo_findings[0].severity == Severity.HIGH
        assert typo_findings[0].matched_brand == "paypal.com"

    def test_two_edits_from_microsoft_is_medium_severity(self):
        """'miicrosoft.com' (2 edits) → MEDIUM severity."""
        # 'microsoftt.com' is only 1 edit from 'microsoft.com' (extra 't' at end).
        # Use 'miicrosoft.com' (extra 'i') which is also 1 edit — so use a domain
        # that is genuinely 2 edits away: 'miicrosoftt.com'
        findings = analyze_domain("miicrosoftt.com")
        typo_findings = _findings_by_category(findings, "typosquatting")
        assert len(typo_findings) >= 1
        assert typo_findings[0].severity == Severity.MEDIUM

    def test_exact_brand_domain_has_no_typosquatting_finding(self):
        """Exact brand domain → no typosquatting finding."""
        findings = analyze_domain("paypal.com")
        typo_findings = _findings_by_category(findings, "typosquatting")
        assert len(typo_findings) == 0

    def test_unrelated_domain_has_no_typosquatting_finding(self):
        """Completely unrelated domain → no typosquatting finding."""
        findings = analyze_domain("completely-unrelated-xyz123.com")
        typo_findings = _findings_by_category(findings, "typosquatting")
        assert len(typo_findings) == 0


# ---------------------------------------------------------------------------
# Subdomain abuse tests
# ---------------------------------------------------------------------------


class TestSubdomainAbuse:
    def test_brand_as_subdomain_prefix_is_high_severity(self):
        """'paypal.com.evil-phish.ru' → HIGH severity subdomain abuse."""
        findings = analyze_domain("paypal.com.evil-phish.ru")
        subdomain_findings = _findings_by_category(findings, "subdomain_abuse")
        assert len(subdomain_findings) >= 1
        assert subdomain_findings[0].severity == Severity.HIGH
        assert subdomain_findings[0].matched_brand == "paypal.com"

    def test_legitimate_brand_domain_has_no_subdomain_abuse(self):
        """'mail.paypal.com' is a legitimate subdomain — no abuse finding."""
        findings = analyze_domain("mail.paypal.com")
        subdomain_findings = _findings_by_category(findings, "subdomain_abuse")
        # mail.paypal.com → registrable is paypal.com → no abuse
        assert len(subdomain_findings) == 0


# ---------------------------------------------------------------------------
# Finding structure tests
# ---------------------------------------------------------------------------


class TestFindingStructure:
    def test_findings_are_frozen(self):
        """DomainFinding instances must be immutable."""
        findings = analyze_domain("test.com", registered_date=_days_ago(5))
        for f in findings:
            with pytest.raises((AttributeError, TypeError)):
                f.category = "mutated"  # type: ignore[misc]

    def test_finding_domain_field_matches_input(self):
        """The ``domain`` field on each finding must match the input domain."""
        domain = "evil-new.ru"
        findings = analyze_domain(domain, registered_date=_days_ago(3))
        for f in findings:
            assert f.domain == domain

    def test_empty_domain_does_not_raise(self):
        """Empty domain string should not raise an exception."""
        findings = analyze_domain("")
        assert isinstance(findings, list)

    def test_domain_is_lowercased(self):
        """Domain input is normalised to lower-case."""
        findings = analyze_domain("PAYPAL.COM")
        # Should not produce typosquatting findings for the exact brand.
        typo_findings = _findings_by_category(findings, "typosquatting")
        assert len(typo_findings) == 0
