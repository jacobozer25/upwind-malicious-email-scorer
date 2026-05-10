"""
backend/app/schemas/response.py
---------------------------------
Pydantic response schema for the ``POST /v1/analyze`` endpoint.

This module defines the versioned DTO (Data Transfer Object) that is
serialised to JSON and returned to the caller.  It maps from the internal
:class:`~app.services.email_analyzer.EmailVerdict` dataclass.

Progressive Disclosure support
===============================
The response is deliberately verbose so that the Gmail Add-on / Chrome
Extension can implement Progressive Disclosure:

* **Summary view** — show ``final_score``, ``risk_level``, and
  ``semantic_warning`` immediately.
* **Detail view** — show ``deterministic_findings`` under a "Show More"
  button.  Each finding includes ``source``, ``category``, ``severity``,
  ``description``, and ``evidence`` so the UI can group and filter them.
* **Future user settings** — the full payload supports a future "Summary
  Only vs Full Technical View" toggle without any API changes.

Design notes
============
* All nested models are Pydantic ``BaseModel`` subclasses so they serialise
  cleanly to JSON.
* ``risk_level`` is a ``str`` enum value (e.g. ``"suspicious"``) — not an
  integer — so the UI can display it directly without a lookup table.
* ``llm_gated`` distinguishes an intentional LLM skip (efficiency/safety)
  from an LLM failure, allowing the UI to show different messages.
"""
from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Nested schemas
# ---------------------------------------------------------------------------


class FindingSchema(BaseModel):
    """A single security finding from the deterministic layer.

    Attributes
    ----------
    id:
        UUID that uniquely identifies this finding instance.
    type:
        Category of the finding (e.g. ``"PHISHING"``, ``"MALWARE"``).
    severity:
        Severity level (``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``).
    description:
        Human-readable description of what was detected.
    evidence:
        Free-form dict of supporting evidence (URLs, header values, etc.).
    source:
        Which analyzer produced this finding (e.g. ``"content"``,
        ``"attachments"``, ``"reputation"``).  Used by the UI to group
        findings under collapsible sections.
    """

    id: uuid.UUID = Field(description="Unique finding identifier.")
    type: str = Field(description="Finding category (e.g. PHISHING, MALWARE).")
    severity: str = Field(description="Severity level: LOW, MEDIUM, HIGH, or CRITICAL.")
    description: str = Field(description="Human-readable description of the finding.")
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting evidence dict (URLs, header values, matched text, etc.).",
    )
    source: str = Field(
        default="deterministic",
        description="Analyzer that produced this finding (for UI grouping).",
    )


class LLMResultSchema(BaseModel):
    """Structured output from the LLM semantic layer.

    Only present in the response when ``llm_available`` is ``True``.
    """

    score: int = Field(
        ge=0, le=100,
        description="LLM semantic score (0–100).",
    )
    semantic_score: int = Field(
        ge=0, le=100,
        description="Alias for score — used by the fusion layer.",
    )
    risk_level: str = Field(description="LLM-assigned risk level.")
    rational: str = Field(description="LLM rationale for the verdict.")
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="LLM-identified findings (semantic signals only).",
    )


# ---------------------------------------------------------------------------
# Top-level response schema
# ---------------------------------------------------------------------------


class AnalyzeEmailResponse(BaseModel):
    """Response body for ``POST /v1/analyze``.

    Attributes
    ----------
    final_score:
        Fused 0–100 maliciousness score.  If the LLM was gated or failed,
        this equals the deterministic score.
    risk_level:
        Categorical risk band: ``"benign"``, ``"suspicious"``,
        ``"likely_malicious"``, or ``"malicious"``.
    deterministic_score:
        The raw deterministic-only score before LLM fusion.  Always present.
    deterministic_findings:
        Complete list of findings from the deterministic layer.  Always
        present and never filtered — the UI decides what to show.
    llm_available:
        ``True`` if the LLM was called and returned a valid response.
    llm_gated:
        ``True`` if the LLM was intentionally skipped by the Smart Gating
        logic (score outside 10–90 range).  ``False`` if the LLM was
        attempted (whether it succeeded or failed).
    llm_result:
        Structured LLM output.  ``None`` if ``llm_available`` is ``False``.
    semantic_warning:
        Human-readable warning shown to the user when ``llm_available`` is
        ``False``.  Empty string when LLM succeeded.
        - Gated: informational (ℹ).
        - Failed: high-visibility security alert (⚠).
    schema_version:
        Response schema version for forward-compatibility.
    """

    final_score: float = Field(
        ge=0.0, le=100.0,
        description="Fused maliciousness score (0–100).",
    )
    risk_level: str = Field(
        description="Risk band: benign | suspicious | likely_malicious | malicious.",
    )
    deterministic_score: float = Field(
        ge=0.0, le=100.0,
        description="Raw deterministic score before LLM fusion.",
    )
    deterministic_findings: list[FindingSchema] = Field(
        default_factory=list,
        description=(
            "All findings from the deterministic layer. "
            "Always complete — the UI applies Progressive Disclosure."
        ),
    )
    llm_available: bool = Field(
        description="True if the LLM was called and returned a valid response.",
    )
    llm_gated: bool = Field(
        description=(
            "True if the LLM was intentionally skipped by Smart Gating. "
            "False if the LLM was attempted (success or failure)."
        ),
    )
    llm_result: LLMResultSchema | None = Field(
        default=None,
        description="Structured LLM output. None if llm_available is False.",
    )
    semantic_warning: str = Field(
        default="",
        description=(
            "Warning shown when llm_available is False. "
            "Empty string when LLM succeeded."
        ),
    )
    explanation: str = Field(
        default="",
        description=(
            "Human-readable summary of the analysis outcome, including an "
            "AI status indicator appended at the end. "
            "Indicates whether AI analysis was skipped, succeeded, or failed."
        ),
    )
    schema_version: str = Field(
        default="1.0",
        description="Response schema version for forward-compatibility.",
    )

    # ── Factory method ────────────────────────────────────────────────────

    @classmethod
    def from_verdict(cls, verdict: object) -> "AnalyzeEmailResponse":
        """Build a response from an internal ``EmailVerdict`` dataclass.

        Args:
            verdict: An :class:`~app.services.email_analyzer.EmailVerdict`
                instance.

        Returns:
            A fully-populated :class:`AnalyzeEmailResponse`.
        """
        # Import here to avoid circular imports.
        from app.services.email_analyzer import EmailVerdict  # noqa: PLC0415

        assert isinstance(verdict, EmailVerdict)

        # Convert domain Finding objects to FindingSchema.
        finding_schemas = [
            FindingSchema(
                id=f.id,
                type=f.type.value,
                severity=f.severity.value,
                description=f.description,
                evidence=f.evidence,
                source=f.evidence.get("signal", "deterministic"),  # type: ignore[arg-type]
            )
            for f in verdict.deterministic_findings
        ]

        # Convert LLM result dict to LLMResultSchema if available.
        llm_schema: LLMResultSchema | None = None
        if verdict.llm_available and verdict.llm_result is not None:
            raw = verdict.llm_result
            llm_schema = LLMResultSchema(
                score=int(raw.get("score", 0)),
                semantic_score=int(raw.get("semantic_score", 0)),
                risk_level=str(raw.get("risk_level", "benign")),
                rational=str(raw.get("rational", "")),
                findings=list(raw.get("findings", [])),
            )

        # ── Build the AI status indicator for the explanation field ──────────
        # Base explanation: use the LLM rationale if available, otherwise empty.
        base_explanation = ""
        if verdict.llm_available and verdict.llm_result is not None:
            base_explanation = str(verdict.llm_result.get("rationale", ""))

        # Append the appropriate AI status suffix based on the pipeline path.
        if verdict.llm_gated:
            ai_status = "\n\n⚙️ AI Analysis: Skipped (Deterministic rules applied)."
        elif verdict.llm_available:
            ai_status = "\n\n🤖 AI Analysis: Performed successfully by Claude 4.5."
        else:
            ai_status = "\n\n⚠️ AI Analysis: Failed or unreachable."

        explanation = base_explanation + ai_status

        return cls(
            final_score=verdict.final_score,
            risk_level=verdict.risk_level.value,
            deterministic_score=verdict.deterministic_score,
            deterministic_findings=finding_schemas,
            llm_available=verdict.llm_available,
            llm_gated=verdict.llm_gated,
            llm_result=llm_schema,
            semantic_warning=verdict.semantic_warning,
            explanation=explanation,
        )
