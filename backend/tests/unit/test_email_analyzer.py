"""
tests/unit/test_email_analyzer.py
-----------------------------------
Unit tests for ``AnalyzeEmailUseCase`` — the orchestrator that combines the
deterministic layer with the LLM layer.

These tests verify:
1. **Happy path** — deterministic + LLM both available → fused verdict.
2. **LLM fallback** — LLM raises an exception → deterministic-only verdict
   with semantic warning.
3. **LLM timeout** — LLM times out → deterministic-only verdict with warning.
4. **LLM not configured** — ``llm_provider=None`` → deterministic-only.
5. **Score fusion** — correct weighted combination of scores.
6. **Risk level thresholds** — correct band assignment for both full and
   deterministic-only paths.
7. **Analyzer failure isolation** — a crashing analyzer does not fail the
   whole request.

All LLM calls are mocked. No real API calls are made.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.email_analyzer import (
    AnalyzeEmailUseCase,
    DeterministicFinding,
    EmailVerdict,
    LLMResult,
    RiskLevel,
    _fuse_scores,
    _risk_level_from_score,
    _score_from_findings,
    _DET_ONLY_THRESHOLDS,
    _FULL_THRESHOLDS,
)


# ---------------------------------------------------------------------------
# Fixtures (supplement conftest.py)
# ---------------------------------------------------------------------------


def _high_finding(source: str = "test") -> DeterministicFinding:
    return DeterministicFinding(
        category="spf", severity="high", detail="SPF fail", source=source
    )


def _medium_finding(source: str = "test") -> DeterministicFinding:
    return DeterministicFinding(
        category="dmarc", severity="medium", detail="DMARC none", source=source
    )


def _low_finding(source: str = "test") -> DeterministicFinding:
    return DeterministicFinding(
        category="dkim", severity="low", detail="DKIM none", source=source
    )


def _make_llm(score: int = 65) -> MagicMock:
    provider = MagicMock()
    provider.analyze = AsyncMock(
        return_value=LLMResult(
            semantic_score=score,
            verdict="likely_malicious",
            confidence="high",
            rationale="Test rationale.",
        )
    )
    return provider


def _make_failing_llm(exc: Exception | None = None) -> MagicMock:
    provider = MagicMock()
    provider.analyze = AsyncMock(
        side_effect=exc or RuntimeError("LLM unavailable")
    )
    return provider


class _CrashingAnalyzer:
    """An analyzer that always raises."""

    async def analyze(self, email: dict[str, Any]) -> list[DeterministicFinding]:
        raise RuntimeError("Analyzer crashed!")


class _SlowAnalyzer:
    """An analyzer that sleeps forever (triggers timeout)."""

    async def analyze(self, email: dict[str, Any]) -> list[DeterministicFinding]:
        await asyncio.sleep(999)
        return []


class _FixedAnalyzer:
    """An analyzer that returns a fixed list of findings."""

    def __init__(self, findings: list[DeterministicFinding]) -> None:
        self._findings = findings

    async def analyze(self, email: dict[str, Any]) -> list[DeterministicFinding]:
        return list(self._findings)


_SAMPLE_EMAIL: dict[str, Any] = {
    "from_address": "attacker@evil.com",
    "subject": "Test",
    "body_text": "Test body",
    "headers": {},
    "attachments": [],
    "received_at_utc": "2026-05-08T10:00:00Z",
}


# ---------------------------------------------------------------------------
# Score helper unit tests (pure functions — no async needed)
# ---------------------------------------------------------------------------


class TestScoreHelpers:
    def test_score_from_no_findings_is_zero(self):
        assert _score_from_findings([]) == 0.0

    def test_score_from_single_high_finding(self):
        assert _score_from_findings([_high_finding()]) == 25.0

    def test_score_capped_at_100(self):
        findings = [_high_finding()] * 10  # 10 × 25 = 250 → capped at 100
        assert _score_from_findings(findings) == 100.0

    def test_score_mixed_severities(self):
        findings = [_high_finding(), _medium_finding(), _low_finding()]
        # 25 + 12 + 4 = 41
        assert _score_from_findings(findings) == 41.0

    def test_fuse_scores_weighted(self):
        # 50 * 0.45 + 50 * 0.55 = 50
        assert _fuse_scores(50.0, 50.0) == 50.0

    def test_fuse_scores_capped_at_100(self):
        assert _fuse_scores(100.0, 100.0) == 100.0

    def test_risk_level_full_thresholds(self):
        assert _risk_level_from_score(85.0, _FULL_THRESHOLDS) == RiskLevel.MALICIOUS
        assert _risk_level_from_score(65.0, _FULL_THRESHOLDS) == RiskLevel.LIKELY_MALICIOUS
        assert _risk_level_from_score(45.0, _FULL_THRESHOLDS) == RiskLevel.SUSPICIOUS
        assert _risk_level_from_score(10.0, _FULL_THRESHOLDS) == RiskLevel.BENIGN

    def test_risk_level_det_only_thresholds_caps_at_likely_malicious(self):
        """Deterministic-only path never returns MALICIOUS."""
        assert _risk_level_from_score(95.0, _DET_ONLY_THRESHOLDS) == RiskLevel.LIKELY_MALICIOUS
        assert _risk_level_from_score(55.0, _DET_ONLY_THRESHOLDS) == RiskLevel.SUSPICIOUS
        assert _risk_level_from_score(10.0, _DET_ONLY_THRESHOLDS) == RiskLevel.BENIGN


# ---------------------------------------------------------------------------
# AnalyzeEmailUseCase async tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAnalyzeEmailUseCase:
    async def test_happy_path_with_llm(self):
        """Deterministic + LLM both available → fused verdict, no warning."""
        findings = [_high_finding(), _medium_finding()]
        use_case = AnalyzeEmailUseCase(
            analyzers=[_FixedAnalyzer(findings)],
            llm_provider=_make_llm(score=70),
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        assert verdict.llm_available is True
        assert verdict.semantic_warning == ""
        assert verdict.llm_result is not None
        assert verdict.llm_result.semantic_score == 70
        assert len(verdict.deterministic_findings) == 2
        # Fused score: (25+12)*0.45 + 70*0.55 = 16.65 + 38.5 = 55.15
        assert verdict.final_score == pytest.approx(55.15, abs=0.1)
        assert verdict.risk_level == RiskLevel.SUSPICIOUS

    async def test_llm_error_triggers_fallback(self):
        """LLM raises → deterministic-only verdict with semantic warning."""
        findings = [_high_finding()]
        use_case = AnalyzeEmailUseCase(
            analyzers=[_FixedAnalyzer(findings)],
            llm_provider=_make_failing_llm(),
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        assert verdict.llm_available is False
        assert verdict.llm_result is None
        assert "Semantic analysis unavailable" in verdict.semantic_warning
        assert verdict.final_score == 25.0  # Deterministic only
        assert verdict.risk_level == RiskLevel.BENIGN  # 25 < 50 threshold

    async def test_llm_timeout_triggers_fallback(self):
        """LLM times out → deterministic-only verdict with semantic warning."""
        findings = [_high_finding(), _high_finding(), _high_finding()]  # score=75
        use_case = AnalyzeEmailUseCase(
            analyzers=[_FixedAnalyzer(findings)],
            llm_provider=_make_failing_llm(asyncio.TimeoutError()),
            llm_timeout_seconds=0.01,  # Very short timeout
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        assert verdict.llm_available is False
        assert "Semantic analysis unavailable" in verdict.semantic_warning

    async def test_no_llm_provider_triggers_fallback(self):
        """llm_provider=None → deterministic-only, no warning about error."""
        findings = [_medium_finding()]
        use_case = AnalyzeEmailUseCase(
            analyzers=[_FixedAnalyzer(findings)],
            llm_provider=None,
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        assert verdict.llm_available is False
        assert verdict.llm_result is None
        # Warning is still shown (user should know semantic analysis is absent).
        assert "Semantic analysis unavailable" in verdict.semantic_warning

    async def test_high_det_score_without_llm_caps_at_likely_malicious(self):
        """Det score ≥ 80 without LLM → LIKELY_MALICIOUS (not MALICIOUS)."""
        findings = [_high_finding()] * 4  # 4 × 25 = 100
        use_case = AnalyzeEmailUseCase(
            analyzers=[_FixedAnalyzer(findings)],
            llm_provider=None,
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        assert verdict.risk_level == RiskLevel.LIKELY_MALICIOUS
        assert verdict.llm_available is False

    async def test_malicious_verdict_requires_llm(self):
        """MALICIOUS verdict only possible when LLM is available."""
        findings = [_high_finding()] * 4  # Det score = 100
        use_case = AnalyzeEmailUseCase(
            analyzers=[_FixedAnalyzer(findings)],
            llm_provider=_make_llm(score=90),
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        assert verdict.llm_available is True
        assert verdict.risk_level == RiskLevel.MALICIOUS

    async def test_crashing_analyzer_does_not_fail_request(self):
        """A crashing analyzer is skipped; the request still completes."""
        use_case = AnalyzeEmailUseCase(
            analyzers=[_CrashingAnalyzer(), _FixedAnalyzer([_low_finding()])],
            llm_provider=None,
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        # Only the non-crashing analyzer's findings are present.
        assert len(verdict.deterministic_findings) == 1
        assert verdict.deterministic_findings[0].severity == "low"

    async def test_slow_analyzer_is_skipped_on_timeout(self):
        """An analyzer that exceeds the timeout is skipped gracefully."""
        use_case = AnalyzeEmailUseCase(
            analyzers=[_SlowAnalyzer(), _FixedAnalyzer([_high_finding()])],
            llm_provider=None,
            analyzer_timeout_seconds=0.01,
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        # Only the fast analyzer's findings are present.
        assert len(verdict.deterministic_findings) == 1

    async def test_empty_email_returns_benign_verdict(self):
        """Empty email with no findings → BENIGN verdict."""
        use_case = AnalyzeEmailUseCase(
            analyzers=[_FixedAnalyzer([])],
            llm_provider=None,
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        assert verdict.final_score == 0.0
        assert verdict.risk_level == RiskLevel.BENIGN

    async def test_verdict_always_returned_never_raises(self):
        """The use case must never raise — it always returns a verdict."""
        use_case = AnalyzeEmailUseCase(
            analyzers=[_CrashingAnalyzer()],
            llm_provider=_make_failing_llm(),
        )
        # Should not raise.
        verdict = await use_case.execute(_SAMPLE_EMAIL)
        assert isinstance(verdict, EmailVerdict)

    async def test_multiple_analyzers_findings_are_combined(self):
        """Findings from multiple analyzers are all included in the verdict."""
        use_case = AnalyzeEmailUseCase(
            analyzers=[
                _FixedAnalyzer([_high_finding("headers")]),
                _FixedAnalyzer([_medium_finding("domains")]),
                _FixedAnalyzer([_low_finding("content")]),
            ],
            llm_provider=None,
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        assert len(verdict.deterministic_findings) == 3
        sources = {f.source for f in verdict.deterministic_findings}
        assert sources == {"headers", "domains", "content"}

    async def test_semantic_warning_contains_guidance(self):
        """The semantic warning must mention verification guidance."""
        use_case = AnalyzeEmailUseCase(
            analyzers=[_FixedAnalyzer([])],
            llm_provider=None,
        )
        verdict = await use_case.execute(_SAMPLE_EMAIL)

        assert "verify" in verdict.semantic_warning.lower()
        assert "separate channel" in verdict.semantic_warning.lower()
