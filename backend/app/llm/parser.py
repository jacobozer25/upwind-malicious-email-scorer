"""
backend/app/llm/parser.py
---------------------------
Robust JSON parser for LLM responses.

Validates Claude's output against the JSON schema defined in Section 4 of
system.md (and extracted to ``prompts/output_schema.json``).

Retry logic
===========
If the first response fails validation, the parser returns a corrective
instruction string that the caller can send back to the LLM as a follow-up
message (1 retry).  The caller is responsible for the retry loop — the
parser itself is stateless.

Fallback
========
If parsing or validation fails after retries, ``parse_llm_response()``
raises ``LLMParseError``.  The caller (``AnthropicProvider``) catches this
and returns the safe "suspicious/low confidence" fallback verdict.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Validation constants (mirrors output_schema.json)
# ---------------------------------------------------------------------------

_VALID_VERDICTS = frozenset({"benign", "suspicious", "likely_malicious", "malicious"})
_VALID_CONFIDENCE = frozenset({"low", "medium", "high"})
_VALID_ACTIONS = frozenset({
    "safe_to_proceed",
    "verify_via_separate_channel",
    "do_not_click_or_reply",
    "report_to_security_team",
})
_VALID_CATEGORIES = frozenset({
    "urgency", "authority", "fear", "scarcity", "impersonation",
    "credential_request", "payment_redirection", "unusual_channel",
    "prompt_injection_attempt", "tone_mismatch",
})
_VALID_SEVERITIES = frozenset({"low", "medium", "high"})

_REQUIRED_FIELDS = frozenset({
    "schema_version", "semantic_score", "verdict", "confidence",
    "social_engineering_indicators", "rationale",
    "recommended_user_action", "uncertainty_notes",
})

# ---------------------------------------------------------------------------
# Corrective retry instruction
# ---------------------------------------------------------------------------

RETRY_INSTRUCTION = (
    "Your previous response was not valid JSON or did not match the required schema. "
    "Return ONLY a single JSON object with these exact fields: "
    "schema_version (string '1.0'), semantic_score (integer 0-100), "
    "verdict (one of: benign/suspicious/likely_malicious/malicious), "
    "confidence (low/medium/high), social_engineering_indicators (array), "
    "rationale (string ≤600 chars), recommended_user_action, uncertainty_notes. "
    "No markdown, no prose, no trailing commas."
)

# ---------------------------------------------------------------------------
# Safe fallback verdict
# ---------------------------------------------------------------------------

SAFE_FALLBACK_VERDICT: dict[str, Any] = {
    "schema_version": "1.0",
    "semantic_score": 40,
    "verdict": "suspicious",
    "confidence": "low",
    "social_engineering_indicators": [],
    "rationale": (
        "Semantic analysis could not be completed due to a parsing error. "
        "This verdict is based on deterministic signals only. "
        "Treat with additional caution."
    ),
    "recommended_user_action": "verify_via_separate_channel",
    "uncertainty_notes": "LLM response could not be parsed or validated.",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class LLMParseError(Exception):
    """Raised when the LLM response cannot be parsed or validated."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_llm_response(raw_response: str) -> dict[str, Any]:
    """Parse and validate a raw LLM response string.

    Args:
        raw_response: The raw text returned by the LLM.

    Returns:
        A validated dict matching the output schema.

    Raises:
        LLMParseError: If the response cannot be parsed as JSON or fails
            schema validation.
    """
    # ── Step 1: Extract JSON from the response ────────────────────────────
    json_str = _extract_json(raw_response)

    # ── Step 2: Parse JSON ────────────────────────────────────────────────
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise LLMParseError(
            f"JSON decode error: {exc}. Raw (first 200 chars): {raw_response[:200]!r}"
        ) from exc

    if not isinstance(data, dict):
        raise LLMParseError(
            f"Expected a JSON object, got {type(data).__name__}."
        )

    # ── Step 3: Validate required fields ─────────────────────────────────
    _validate(data)

    log.debug(
        "parser.response_valid",
        extra={
            "verdict": data.get("verdict"),
            "semantic_score": data.get("semantic_score"),
            "confidence": data.get("confidence"),
            "indicator_count": len(data.get("social_engineering_indicators", [])),
        },
    )

    return data


def is_valid_response(raw_response: str) -> bool:
    """Return True if the raw response passes parsing and validation."""
    try:
        parse_llm_response(raw_response)
        return True
    except LLMParseError:
        return False


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _extract_json(text: str) -> str:
    """Extract a JSON object from a string that may contain prose or fences.

    Handles:
    * Pure JSON (most common — the prompt enforces this).
    * JSON wrapped in ```json ... ``` markdown fences (occasional drift).
    * JSON preceded or followed by a short prose sentence.
    """
    text = text.strip()

    # Fast path: already valid JSON
    if text.startswith("{"):
        return text

    # Try to strip markdown code fences
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence_match:
        return fence_match.group(1)

    # Try to find the first { ... } block
    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        return brace_match.group(0)

    raise LLMParseError(
        f"No JSON object found in LLM response. "
        f"Raw (first 200 chars): {text[:200]!r}"
    )


def _validate(data: dict[str, Any]) -> None:
    """Validate a parsed dict against the output schema.

    Raises:
        LLMParseError: On any schema violation.
    """
    # Required fields
    missing = _REQUIRED_FIELDS - data.keys()
    if missing:
        raise LLMParseError(f"Missing required fields: {sorted(missing)}")

    # schema_version
    if data["schema_version"] != "1.0":
        raise LLMParseError(
            f"Invalid schema_version: {data['schema_version']!r}. Expected '1.0'."
        )

    # semantic_score
    score = data["semantic_score"]
    if not isinstance(score, int) or not (0 <= score <= 100):
        raise LLMParseError(
            f"semantic_score must be an integer 0–100, got {score!r}."
        )

    # verdict
    if data["verdict"] not in _VALID_VERDICTS:
        raise LLMParseError(
            f"Invalid verdict: {data['verdict']!r}. "
            f"Must be one of {sorted(_VALID_VERDICTS)}."
        )

    # confidence
    if data["confidence"] not in _VALID_CONFIDENCE:
        raise LLMParseError(
            f"Invalid confidence: {data['confidence']!r}. "
            f"Must be one of {sorted(_VALID_CONFIDENCE)}."
        )

    # recommended_user_action
    if data["recommended_user_action"] not in _VALID_ACTIONS:
        raise LLMParseError(
            f"Invalid recommended_user_action: {data['recommended_user_action']!r}."
        )

    # social_engineering_indicators
    indicators = data["social_engineering_indicators"]
    if not isinstance(indicators, list):
        raise LLMParseError("social_engineering_indicators must be an array.")

    for i, ind in enumerate(indicators):
        if not isinstance(ind, dict):
            raise LLMParseError(
                f"social_engineering_indicators[{i}] must be an object."
            )
        for field in ("category", "severity", "evidence_quote", "explanation"):
            if field not in ind:
                raise LLMParseError(
                    f"social_engineering_indicators[{i}] missing field '{field}'."
                )
        if ind["category"] not in _VALID_CATEGORIES:
            raise LLMParseError(
                f"social_engineering_indicators[{i}].category invalid: "
                f"{ind['category']!r}."
            )
        if ind["severity"] not in _VALID_SEVERITIES:
            raise LLMParseError(
                f"social_engineering_indicators[{i}].severity invalid: "
                f"{ind['severity']!r}."
            )

    # String field length caps
    if len(data.get("rationale", "")) > 600:
        raise LLMParseError("rationale exceeds 600 characters.")
    if len(data.get("uncertainty_notes", "")) > 300:
        raise LLMParseError("uncertainty_notes exceeds 300 characters.")
