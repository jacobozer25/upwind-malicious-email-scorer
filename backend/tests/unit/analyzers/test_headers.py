"""
tests/unit/analyzers/test_headers.py
--------------------------------------
Unit tests for the deterministic SPF/DKIM/DMARC header analyzer.

These tests exercise ``app.analyzers.headers.analyze_headers`` in complete
isolation — no LLM, no network, no database. Each test is a pure function
call with a dict of headers and an assertion on the returned findings.

Test categories
===============
* SPF: pass, fail, softfail, none, missing header
* DKIM: pass, fail, none, missing header, signature-present-but-unverified
* DMARC: pass, fail, none, missing header
* Combined: all-pass, all-fail, mixed
* Edge cases: empty headers, case-insensitive header names, truncated values
"""
from __future__ import annotations

import pytest

from app.analyzers.headers import (
    AuthResult,
    Finding,
    Severity,
    analyze_headers,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _findings_by_category(findings: list[Finding], category: str) -> list[Finding]:
    return [f for f in findings if f.category == category]


def _single(findings: list[Finding], category: str) -> Finding:
    """Assert exactly one finding for the given category and return it."""
    matches = _findings_by_category(findings, category)
    assert len(matches) == 1, (
        f"Expected exactly 1 '{category}' finding, got {len(matches)}: {matches}"
    )
    return matches[0]


# ---------------------------------------------------------------------------
# SPF tests
# ---------------------------------------------------------------------------


class TestSPF:
    def test_spf_pass(self):
        headers = {
            "Authentication-Results": (
                "mx.google.com; spf=pass smtp.mailfrom=example.com"
            )
        }
        findings = analyze_headers(headers)
        f = _single(findings, "spf")
        assert f.result == AuthResult.PASS
        assert f.severity == Severity.LOW

    def test_spf_fail_is_high_severity(self):
        headers = {
            "Authentication-Results": "mx.google.com; spf=fail smtp.mailfrom=evil.com"
        }
        findings = analyze_headers(headers)
        f = _single(findings, "spf")
        assert f.result == AuthResult.FAIL
        assert f.severity == Severity.HIGH

    def test_spf_softfail_is_medium_severity(self):
        headers = {
            "Authentication-Results": "mx.google.com; spf=softfail smtp.mailfrom=example.com"
        }
        findings = analyze_headers(headers)
        f = _single(findings, "spf")
        assert f.result == AuthResult.SOFTFAIL
        assert f.severity == Severity.MEDIUM

    def test_spf_none_in_auth_results(self):
        headers = {"Authentication-Results": "mx.google.com; spf=none"}
        findings = analyze_headers(headers)
        f = _single(findings, "spf")
        assert f.result == AuthResult.NONE
        assert f.severity == Severity.LOW

    def test_spf_fallback_to_received_spf_header(self):
        """When Authentication-Results has no SPF, fall back to Received-SPF."""
        headers = {
            "Authentication-Results": "mx.google.com; dkim=pass",
            "Received-SPF": "pass (google.com: domain of sender@example.com)",
        }
        findings = analyze_headers(headers)
        f = _single(findings, "spf")
        assert f.result == AuthResult.PASS

    def test_spf_missing_emits_none_finding(self):
        """No SPF header at all → LOW severity 'none' finding."""
        headers = {}
        findings = analyze_headers(headers)
        f = _single(findings, "spf")
        assert f.result == AuthResult.NONE
        assert f.severity == Severity.LOW

    def test_spf_case_insensitive_header_name(self):
        """Header names should be compared case-insensitively."""
        headers = {
            "authentication-results": "mx.google.com; spf=pass"
        }
        findings = analyze_headers(headers)
        f = _single(findings, "spf")
        assert f.result == AuthResult.PASS

    def test_spf_temperror(self):
        headers = {"Authentication-Results": "mx.google.com; spf=temperror"}
        findings = analyze_headers(headers)
        f = _single(findings, "spf")
        assert f.result == AuthResult.TEMPERROR
        assert f.severity == Severity.LOW  # Transient — not a hard signal


# ---------------------------------------------------------------------------
# DKIM tests
# ---------------------------------------------------------------------------


class TestDKIM:
    def test_dkim_pass(self):
        headers = {
            "Authentication-Results": (
                "mx.google.com; dkim=pass header.i=@example.com"
            )
        }
        findings = analyze_headers(headers)
        f = _single(findings, "dkim")
        assert f.result == AuthResult.PASS
        assert f.severity == Severity.LOW

    def test_dkim_fail_is_high_severity(self):
        headers = {
            "Authentication-Results": "mx.google.com; dkim=fail"
        }
        findings = analyze_headers(headers)
        f = _single(findings, "dkim")
        assert f.result == AuthResult.FAIL
        assert f.severity == Severity.HIGH

    def test_dkim_none_in_auth_results(self):
        headers = {"Authentication-Results": "mx.google.com; dkim=none"}
        findings = analyze_headers(headers)
        f = _single(findings, "dkim")
        assert f.result == AuthResult.NONE
        assert f.severity == Severity.LOW

    def test_dkim_signature_present_but_no_auth_results(self):
        """DKIM-Signature present but no Authentication-Results → LOW finding."""
        headers = {
            "DKIM-Signature": "v=1; a=rsa-sha256; d=example.com; s=selector1; ...",
        }
        findings = analyze_headers(headers)
        f = _single(findings, "dkim")
        assert f.result == AuthResult.NONE
        assert f.severity == Severity.LOW
        assert "not have verified" in f.detail

    def test_dkim_missing_entirely(self):
        """No DKIM header at all → LOW severity 'none' finding."""
        headers = {}
        findings = analyze_headers(headers)
        f = _single(findings, "dkim")
        assert f.result == AuthResult.NONE
        assert f.severity == Severity.LOW

    def test_dkim_permerror_is_high_severity(self):
        headers = {"Authentication-Results": "mx.google.com; dkim=permerror"}
        findings = analyze_headers(headers)
        f = _single(findings, "dkim")
        assert f.result == AuthResult.PERMERROR
        assert f.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# DMARC tests
# ---------------------------------------------------------------------------


class TestDMARC:
    def test_dmarc_pass(self):
        headers = {
            "Authentication-Results": "mx.google.com; dmarc=pass"
        }
        findings = analyze_headers(headers)
        f = _single(findings, "dmarc")
        assert f.result == AuthResult.PASS
        assert f.severity == Severity.LOW

    def test_dmarc_fail_is_high_severity(self):
        headers = {
            "Authentication-Results": "mx.google.com; dmarc=fail"
        }
        findings = analyze_headers(headers)
        f = _single(findings, "dmarc")
        assert f.result == AuthResult.FAIL
        assert f.severity == Severity.HIGH

    def test_dmarc_none_is_medium_severity(self):
        headers = {"Authentication-Results": "mx.google.com; dmarc=none"}
        findings = analyze_headers(headers)
        f = _single(findings, "dmarc")
        assert f.result == AuthResult.NONE
        assert f.severity == Severity.MEDIUM

    def test_dmarc_missing_emits_medium_finding(self):
        """No DMARC in Authentication-Results → MEDIUM severity finding."""
        headers = {}
        findings = analyze_headers(headers)
        f = _single(findings, "dmarc")
        assert f.result == AuthResult.NONE
        assert f.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Combined / integration-style tests
# ---------------------------------------------------------------------------


class TestCombined:
    def test_all_pass_produces_three_low_findings(self):
        headers = {
            "Authentication-Results": (
                "mx.google.com; "
                "spf=pass smtp.mailfrom=example.com; "
                "dkim=pass header.i=@example.com; "
                "dmarc=pass"
            )
        }
        findings = analyze_headers(headers)
        assert len(findings) == 3
        for f in findings:
            assert f.severity == Severity.LOW, f"Expected LOW for {f.category}, got {f.severity}"

    def test_all_fail_produces_three_high_findings(self):
        headers = {
            "Authentication-Results": (
                "mx.google.com; "
                "spf=fail; "
                "dkim=fail; "
                "dmarc=fail"
            )
        }
        findings = analyze_headers(headers)
        spf = _single(findings, "spf")
        dkim = _single(findings, "dkim")
        dmarc = _single(findings, "dmarc")
        assert spf.severity == Severity.HIGH
        assert dkim.severity == Severity.HIGH
        assert dmarc.severity == Severity.HIGH

    def test_mixed_results(self):
        """SPF pass, DKIM fail, DMARC fail — common in forwarded phishing."""
        headers = {
            "Authentication-Results": (
                "mx.google.com; "
                "spf=pass; "
                "dkim=fail; "
                "dmarc=fail"
            )
        }
        findings = analyze_headers(headers)
        assert _single(findings, "spf").severity == Severity.LOW
        assert _single(findings, "dkim").severity == Severity.HIGH
        assert _single(findings, "dmarc").severity == Severity.HIGH

    def test_empty_headers_returns_three_findings(self):
        """Empty headers dict → three 'none' findings (one per check)."""
        findings = analyze_headers({})
        categories = {f.category for f in findings}
        assert categories == {"spf", "dkim", "dmarc"}

    def test_findings_are_frozen(self):
        """Findings must be immutable (frozen dataclasses)."""
        findings = analyze_headers({})
        for f in findings:
            with pytest.raises((AttributeError, TypeError)):
                f.category = "mutated"  # type: ignore[misc]

    def test_raw_header_is_truncated_to_500_chars(self):
        """Raw header stored in finding must not exceed 500 chars."""
        long_value = "spf=pass " + "x" * 1000
        headers = {"Authentication-Results": long_value}
        findings = analyze_headers(headers)
        for f in findings:
            assert len(f.raw_header) <= 500
