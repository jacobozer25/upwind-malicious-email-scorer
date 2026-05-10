"""
backend/tests/conftest.py
--------------------------
Shared pytest fixtures for the Malicious Email Scorer test suite.

Fixtures defined here are available to all tests without explicit import.
They cover:

* **Fake LLM provider** — returns a canned ``LLMResult`` so tests never
  make real API calls.
* **Fake LLM that raises** — simulates provider unavailability for fallback
  tests.
* **Sample email dicts** — minimal, benign, and phishing-grade fixtures.
* **Fake analyzer** — a configurable stub that returns pre-set findings.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.email_analyzer import (
    AnalyzeEmailUseCase,
    DeterministicFinding,
    LLMResult,
)


# ---------------------------------------------------------------------------
# Sample email fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def benign_email() -> dict[str, Any]:
    """A minimal, clearly benign email dict."""
    return {
        "message_id": "<benign-001@example.com>",
        "from_address": "newsletter@established-brand.com",
        "subject": "Your weekly digest",
        "body_text": "Here is your weekly digest. Unsubscribe at any time.",
        "headers": {
            "Authentication-Results": (
                "mx.google.com; "
                "spf=pass smtp.mailfrom=established-brand.com; "
                "dkim=pass header.i=@established-brand.com; "
                "dmarc=pass"
            ),
            "Received-SPF": "pass",
        },
        "attachments": [],
        "received_at_utc": "2026-05-08T10:00:00Z",
        "domain_registered_date": "2010-01-15",
    }


@pytest.fixture
def phishing_email() -> dict[str, Any]:
    """A high-risk phishing email dict with multiple red flags."""
    return {
        "message_id": "<phish-001@paypa1-billing.ru>",
        "from_address": "security@paypa1-billing.ru",
        "subject": "URGENT: Your account will be suspended in 24 hours",
        "body_text": (
            "Dear Customer, your PayPal account has been flagged for suspicious "
            "activity. You must verify your identity within 24 hours or your "
            "account will be permanently suspended. Click here to verify: "
            "http://paypa1-billing.ru/verify"
        ),
        "headers": {
            "Authentication-Results": (
                "mx.google.com; "
                "spf=softfail smtp.mailfrom=paypa1-billing.ru; "
                "dkim=fail; "
                "dmarc=fail"
            ),
        },
        "attachments": [],
        "received_at_utc": "2026-05-08T03:14:00Z",
        "domain_registered_date": "2026-05-01",  # 7 days old
    }


@pytest.fixture
def no_auth_headers_email() -> dict[str, Any]:
    """An email with no authentication headers at all."""
    return {
        "message_id": "<noauth-001@unknown.example>",
        "from_address": "sender@unknown.example",
        "subject": "Hello",
        "body_text": "Just a test email.",
        "headers": {},
        "attachments": [],
        "received_at_utc": "2026-05-08T12:00:00Z",
        "domain_registered_date": None,
    }


# ---------------------------------------------------------------------------
# Fake LLM provider fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_llm_result() -> LLMResult:
    """A canned LLM result for a suspicious email."""
    return LLMResult(
        semantic_score=65,
        verdict="likely_malicious",
        confidence="high",
        rationale=(
            "The email uses urgency framing ('24 hours', 'suspended') and "
            "impersonates a financial institution. The call to action directs "
            "the user to a lookalike domain."
        ),
        social_engineering_indicators=[
            {
                "category": "urgency",
                "severity": "high",
                "evidence_quote": "account will be suspended in 24 hours",
                "explanation": "Classic urgency framing to bypass rational evaluation.",
            },
            {
                "category": "impersonation",
                "severity": "high",
                "evidence_quote": "PayPal account has been flagged",
                "explanation": "Impersonates PayPal while sending from a lookalike domain.",
            },
        ],
        recommended_user_action="report_to_security_team",
        uncertainty_notes="",
    )


@pytest.fixture
def fake_llm_provider(fake_llm_result: LLMResult) -> MagicMock:
    """A fake LLM provider that returns a canned result."""
    provider = MagicMock()
    provider.analyze = AsyncMock(return_value=fake_llm_result)
    return provider


@pytest.fixture
def unavailable_llm_provider() -> MagicMock:
    """A fake LLM provider that always raises (simulates outage)."""
    provider = MagicMock()
    provider.analyze = AsyncMock(
        side_effect=RuntimeError("LLM provider unavailable: connection refused")
    )
    return provider


@pytest.fixture
def timeout_llm_provider() -> MagicMock:
    """A fake LLM provider that always times out."""

    async def _slow_analyze(*args: Any, **kwargs: Any) -> LLMResult:
        await asyncio.sleep(999)  # Will be cancelled by wait_for timeout.
        return LLMResult()  # Never reached.

    provider = MagicMock()
    provider.analyze = _slow_analyze
    return provider


# ---------------------------------------------------------------------------
# Fake analyzer fixture
# ---------------------------------------------------------------------------


class FakeAnalyzer:
    """A configurable stub analyzer that returns pre-set findings."""

    def __init__(self, findings: list[DeterministicFinding]) -> None:
        self._findings = findings

    async def analyze(self, email: dict[str, Any]) -> list[DeterministicFinding]:
        return list(self._findings)


@pytest.fixture
def make_fake_analyzer():
    """Factory fixture: returns a FakeAnalyzer with the given findings."""

    def _factory(findings: list[DeterministicFinding]) -> FakeAnalyzer:
        return FakeAnalyzer(findings)

    return _factory


# ---------------------------------------------------------------------------
# Use case factory fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def make_use_case(make_fake_analyzer):
    """Factory fixture: build an AnalyzeEmailUseCase with injected fakes."""

    def _factory(
        findings: list[DeterministicFinding] | None = None,
        llm_provider: Any = None,
        llm_timeout: float = 5.0,
    ) -> AnalyzeEmailUseCase:
        analyzer = make_fake_analyzer(findings or [])
        return AnalyzeEmailUseCase(
            analyzers=[analyzer],
            llm_provider=llm_provider,
            llm_timeout_seconds=llm_timeout,
        )

    return _factory
