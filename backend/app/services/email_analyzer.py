"""
backend/app/services/email_analyzer.py
---------------------------------------
``AnalyzeEmailUseCase`` — the single orchestrator for the full email-scoring
pipeline.

This is the **only** place in the codebase that knows about both the
deterministic layer and the LLM layer. Everything else is a pure function or
an adapter behind a Protocol.

Pipeline
========
1. Run all deterministic analyzers in parallel via
   :class:`~app.analyzers.orchestrator.AnalyzerOrchestrator`.
2. Calculate the deterministic score using
   :func:`~app.scoring.fusion.calculate_deterministic_score`.
3. **Smart Gating**: decide whether to call the LLM:
   - Score < 10.0  → skip LLM (benign, efficiency gate).
   - Score > 90.0  → skip LLM (definitive technical evidence, safety gate).
   - 10.0 ≤ score ≤ 90.0 → attempt LLM call (gray zone).
4. If LLM is called and succeeds: fuse scores with
   :func:`~app.scoring.fusion.fuse_scores` and use ``FULL_THRESHOLDS``.
5. If LLM is gated: use ``DET_ONLY_THRESHOLDS`` with an *informational*
   ``semantic_warning``.
6. If LLM is attempted but fails/times out: use ``DET_ONLY_THRESHOLDS``
   with a *high-visibility security alert* ``semantic_warning``.

LLM fallback contract
=====================
* ``llm_available: False`` in all non-LLM paths.
* ``semantic_warning``:
  - Gated (efficiency/safety): informational note.
  - Failed/timeout: high-visibility security alert.
* Deterministic findings are **always** returned in full regardless of path.

Progressive Disclosure support
===============================
Every :class:`~app.domain.models.Finding` carries ``type`` (Category) and
``severity`` so the Chrome Extension / Gmail Add-on can:
* Show a summary badge (score + risk_level) immediately.
* Hide detailed findings under a "Show More" button.
* Support future user settings (Summary Only vs Full Technical View).

Design notes
============
* The use case is a class so it can be injected with fake analyzers and a
  fake LLM provider in tests.
* The use case does NOT import FastAPI, Pydantic, or any HTTP framework.
  It operates on domain objects only.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from app.analyzers.orchestrator import AnalyzerOrchestrator
from app.domain.models import EmailContext, Finding
from app.domain.ports import AnalyzerPort, LLMPort
from app.scoring.fusion import calculate_deterministic_score, fuse_scores
from app.scoring.thresholds import (
    DET_ONLY_THRESHOLDS,
    FULL_THRESHOLDS,
    LLM_LOWER_THRESHOLD,
    LLM_UPPER_THRESHOLD,
    SEMANTIC_WARNING_FAILED,
    SEMANTIC_WARNING_GATED,
    RiskLevel,
    score_to_risk_level,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class EmailVerdict:
    """The final fused verdict returned to the caller.

    Attributes
    ----------
    final_score:
        Fused 0–100 maliciousness score (rounded to 1 decimal place).
    risk_level:
        Categorical risk band derived from ``final_score``.
    deterministic_findings:
        All findings from the deterministic layer.  Always present and
        complete — never filtered.  Includes ``type`` (Category) and
        ``severity`` for Progressive Disclosure support.
    deterministic_score:
        The raw deterministic-only score before LLM fusion.
    llm_result:
        The raw LLM output dict (``None`` if LLM was not called or failed).
    llm_available:
        ``True`` if the LLM was called and returned a valid response.
    llm_gated:
        ``True`` if the LLM was intentionally skipped by the gating logic.
    semantic_warning:
        Human-readable warning shown to the user when ``llm_available`` is
        ``False``.  Empty string when LLM was available and succeeded.
    """

    final_score: float
    risk_level: RiskLevel
    deterministic_findings: list[Finding]
    deterministic_score: float
    llm_result: dict[str, Any] | None
    llm_available: bool
    llm_gated: bool
    semantic_warning: str = ""


# ---------------------------------------------------------------------------
# Use case
# ---------------------------------------------------------------------------


class AnalyzeEmailUseCase:
    """Orchestrate the full email-scoring pipeline.

    Parameters
    ----------
    analyzers:
        List of :class:`~app.domain.ports.AnalyzerPort` instances.
        Passed directly to :class:`~app.analyzers.orchestrator.AnalyzerOrchestrator`.
    llm_provider:
        The LLM provider instance implementing :class:`~app.domain.ports.LLMPort`.
        Pass ``None`` to run in deterministic-only mode.
    llm_timeout_seconds:
        Timeout for the LLM call.  On timeout the fallback path is taken
        and a high-visibility security alert is shown.
    """

    def __init__(
        self,
        analyzers: list[AnalyzerPort],
        llm_provider: LLMPort | None = None,
        *,
        llm_timeout_seconds: float = 10.0,
    ) -> None:
        self._orchestrator = AnalyzerOrchestrator(analyzers=analyzers)
        self._llm = llm_provider
        self._llm_timeout = llm_timeout_seconds

    async def execute(self, context: EmailContext) -> EmailVerdict:
        """Run the full pipeline and return a verdict.

        Args:
            context: The :class:`~app.domain.models.EmailContext` to analyze.

        Returns:
            An :class:`EmailVerdict`.  Always returned — never raises.
        """
        # ── Step 1: Run all deterministic analyzers in parallel. ─────────
        findings: list[Finding] = await self._orchestrator.analyze_all(context)

        # ── Step 2: Calculate deterministic score. ───────────────────────
        det_score = calculate_deterministic_score(findings)

        log.info(
            "deterministic_layer.complete",
            extra={
                "finding_count": len(findings),
                "det_score": round(det_score, 1),
            },
        )

        # ── Step 3: Smart Gating — decide whether to call the LLM. ──────
        in_gray_zone = LLM_LOWER_THRESHOLD <= det_score <= LLM_UPPER_THRESHOLD

        if not in_gray_zone or self._llm is None:
            # Gate the LLM: either score is outside the gray zone, or no
            # LLM provider is configured.
            gate_reason = (
                "no_llm_provider" if self._llm is None
                else ("below_lower_threshold" if det_score < LLM_LOWER_THRESHOLD
                      else "above_upper_threshold")
            )
            log.info(
                "llm.gated",
                extra={
                    "det_score": round(det_score, 1),
                    "reason": gate_reason,
                },
            )
            final_score = det_score
            risk_level = score_to_risk_level(final_score, DET_ONLY_THRESHOLDS)
            return EmailVerdict(
                final_score=round(final_score, 1),
                risk_level=risk_level,
                deterministic_findings=findings,
                deterministic_score=round(det_score, 1),
                llm_result=None,
                llm_available=False,
                llm_gated=True,
                semantic_warning=SEMANTIC_WARNING_GATED,
            )

        # ── Step 4: Attempt LLM call (gray zone). ────────────────────────
        llm_result_raw, llm_available = await self._run_llm(context, findings)

        if llm_available and llm_result_raw is not None:
            # Extract the LLM semantic score (0–100).
            llm_score = float(llm_result_raw.get("semantic_score", det_score))
            final_score = fuse_scores(det_score, llm_score)
            risk_level = score_to_risk_level(final_score, FULL_THRESHOLDS)
            semantic_warning = ""
            log.info(
                "verdict.produced",
                extra={
                    "det_score": round(det_score, 1),
                    "llm_score": round(llm_score, 1),
                    "final_score": round(final_score, 1),
                    "risk_level": risk_level.value,
                    "llm_available": True,
                },
            )
        else:
            # LLM was attempted but failed — high-visibility security alert.
            final_score = det_score
            risk_level = score_to_risk_level(final_score, DET_ONLY_THRESHOLDS)
            semantic_warning = SEMANTIC_WARNING_FAILED
            log.warning(
                "verdict.produced_without_llm",
                extra={
                    "det_score": round(det_score, 1),
                    "final_score": round(final_score, 1),
                    "risk_level": risk_level.value,
                    "llm_available": False,
                },
            )

        return EmailVerdict(
            final_score=round(final_score, 1),
            risk_level=risk_level,
            deterministic_findings=findings,
            deterministic_score=round(det_score, 1),
            llm_result=llm_result_raw,
            llm_available=llm_available,
            llm_gated=False,
            semantic_warning=semantic_warning,
        )

    # ── Private helpers ────────────────────────────────────────────────────

    async def _run_llm(
        self,
        context: EmailContext,
        findings: list[Finding],
    ) -> tuple[dict[str, Any] | None, bool]:
        """Attempt the LLM call; return (raw_result_dict, available) tuple.

        Returns
        -------
        tuple[dict | None, bool]
            ``(result_dict, True)`` on success.
            ``(None, False)`` on any failure (timeout, provider error).
        """
        assert self._llm is not None  # Guarded by caller

        try:
            verdict = await asyncio.wait_for(
                self._llm.analyze_semantic(context, findings),
                timeout=self._llm_timeout,
            )
            # ``verdict`` may be:
            #   (a) a plain dict returned by AnthropicProvider (most common), or
            #   (b) an AnalysisVerdict dataclass returned by other providers.
            # Normalise both cases into a plain dict so the rest of the pipeline
            # can use dict.get() safely.
            if isinstance(verdict, dict):
                result_dict: dict[str, Any] = {
                    # Prefer "semantic_score" (LLM output schema field name);
                    # fall back to "score" for legacy providers.
                    "score": verdict.get("semantic_score", verdict.get("score", 0)),
                    "semantic_score": verdict.get("semantic_score", verdict.get("score", 0)),
                    "verdict": verdict.get("verdict", "suspicious"),
                    "confidence": verdict.get("confidence", "low"),
                    "risk_level": verdict.get("risk_level", ""),
                    "rational": verdict.get("rationale", verdict.get("rational", "")),
                    "rationale": verdict.get("rationale", verdict.get("rational", "")),
                    "recommended_user_action": verdict.get("recommended_user_action", ""),
                    "uncertainty_notes": verdict.get("uncertainty_notes", ""),
                    "social_engineering_indicators": verdict.get(
                        "social_engineering_indicators", []
                    ),
                    "schema_version": verdict.get("schema_version", "1.0"),
                    # LLM providers don't produce domain Finding objects;
                    # surface the social engineering indicators instead.
                    "findings": verdict.get("social_engineering_indicators", []),
                }
            else:
                # Dataclass / object path (legacy / other providers)
                result_dict = {
                    "score": getattr(verdict, "score", 0),
                    "semantic_score": getattr(verdict, "score", 0),
                    "verdict": "suspicious",
                    "confidence": "low",
                    "risk_level": getattr(verdict.risk_level, "value", "")
                        if hasattr(verdict, "risk_level") else "",
                    "rational": getattr(verdict, "rational", ""),
                    "rationale": getattr(verdict, "rational", ""),
                    "recommended_user_action": "",
                    "uncertainty_notes": "",
                    "social_engineering_indicators": [],
                    "schema_version": "1.0",
                    "findings": [
                        {
                            "id": str(f.id),
                            "type": f.type.value,
                            "severity": f.severity.value,
                            "description": f.description,
                            "evidence": f.evidence,
                            "source": "llm",
                        }
                        for f in getattr(verdict, "findings", [])
                    ],
                }
            return result_dict, True

        except asyncio.TimeoutError:
            log.warning(
                "llm.timeout",
                extra={"timeout_seconds": self._llm_timeout},
            )
            return None, False

        except Exception as exc:  # noqa: BLE001
            log.error(
                "llm.error",
                extra={"error": str(exc)[:300]},
                exc_info=True,
            )
            return None, False


# ---------------------------------------------------------------------------
# Dependency injection helper (used by FastAPI Depends())
# ---------------------------------------------------------------------------


def get_use_case() -> AnalyzeEmailUseCase:
    """Build and return the production use case with all real analyzers.

    This function is called once per request by FastAPI's dependency
    injection system.  In tests, override this dependency with a factory
    that injects fake analyzers and a fake LLM provider.
    """
    from app.analyzers.attachments import AttachmentsAnalyzer  # noqa: PLC0415
    from app.analyzers.content import ContentAnalyzer  # noqa: PLC0415
    from app.analyzers.reputation import ReputationAnalyzer  # noqa: PLC0415
    from app.analyzers.temporal import TemporalAnalyzer  # noqa: PLC0415

    # LLM provider — loaded from config; None if not configured.
    llm_provider: LLMPort | None = None
    try:
        from app.llm.client import get_llm_provider  # noqa: PLC0415
        from app.config import get_settings  # noqa: PLC0415

        settings = get_settings()
        llm_provider = get_llm_provider(settings)  # type: ignore[assignment]
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "use_case.llm_provider_unavailable",
            extra={"error": str(exc)[:200]},
        )

    return AnalyzeEmailUseCase(
        analyzers=[
            AttachmentsAnalyzer(),
            ContentAnalyzer(),
            TemporalAnalyzer(),
            ReputationAnalyzer(),
        ],
        llm_provider=llm_provider,
    )
