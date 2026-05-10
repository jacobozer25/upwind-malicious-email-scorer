"""
backend/app/llm/providers/anthropic_provider.py
-------------------------------------------------
Anthropic (Claude) LLM provider — bridge between the service layer and the
LLM infrastructure.

This provider implements the full pipeline:
  1. Check the semantic cache (Redis) — return cached verdict on hit.
  2. Sanitize the email body via ``sanitizer.py``.
  3. Build the structured prompt (system.md + user-message envelope).
  4. Call Claude Opus 4.5.
  5. Parse and validate the response via ``parser.py`` (1 retry on failure).
  6. Store the validated verdict in the cache.
  7. On any failure after retries, return the safe fallback verdict.

The ``analyze_semantic`` method signature matches the ``LLMPort`` ABC defined
in ``app.domain.ports``.
"""
from __future__ import annotations

import json
import logging
import pathlib
from typing import Any

log = logging.getLogger(__name__)

# Path to the system prompt file (loaded once at class instantiation).
_SYSTEM_PROMPT_PATH = pathlib.Path(__file__).parent.parent / "prompts" / "system.md"

# The system prompt is the text block between the ````text` fences in system.md.
# We extract it at load time so we don't re-parse on every request.
_PROMPT_VERSION = "v1.0.0"


def _load_system_prompt() -> str:
    """Extract the prompt text from system.md (between the ````text` fences)."""
    try:
        raw = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
        # Extract content between the first ```text ... ``` block
        import re
        match = re.search(r"````text\n(.*?)````", raw, re.DOTALL)
        if match:
            return match.group(1).strip()
        # Fallback: return the whole file if no fences found
        log.warning("anthropic_provider.system_prompt_no_fences_found")
        return raw
    except FileNotFoundError:
        log.error(
            "anthropic_provider.system_prompt_missing",
            extra={"path": str(_SYSTEM_PROMPT_PATH)},
        )
        raise


class AnthropicProvider:
    """Anthropic Claude provider implementing the LLMPort interface."""

    def __init__(self, settings: Any) -> None:
        from anthropic import AsyncAnthropic  # noqa: PLC0415

        api_key = getattr(settings, "anthropic_api_key", None)
        # Handle both SecretStr (pydantic) and plain str
        if hasattr(api_key, "get_secret_value"):
            api_key = api_key.get_secret_value()

        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY is missing from environment variables.")

        self.client = AsyncAnthropic(api_key=api_key)
        self.model: str = getattr(settings, "llm_model", "claude-opus-4-5")
        self._system_prompt: str = _load_system_prompt()
        self._max_tokens: int = 1024
        self._temperature: float = 0.0  # system.md specifies temperature 0

        log.info(
            "anthropic_provider.initialized",
            extra={"model": self.model, "prompt_version": _PROMPT_VERSION},
        )

    async def healthcheck(self) -> None:
        """Verify the provider is configured (no API call made)."""
        log.info(
            "anthropic_provider.healthcheck_passed",
            extra={"model": self.model},
        )

    async def analyze_semantic(
        self,
        context: str,
        findings: dict[str, Any] | list[Any],
    ) -> dict[str, Any]:
        """Run semantic analysis on an email using Claude.

        This is the primary method called by the service layer.

        Args:
            context: The email body (plain text). Will be sanitized internally.
            findings: The deterministic findings from the analyzer layer.
                Can be a dict or list — will be serialized to JSON.

        Returns:
            A validated verdict dict matching the output schema (Section 4
            of system.md).  On any failure, returns the safe fallback verdict.
        """
        from app.llm.sanitizer import sanitize_email_body, redact_pii_for_logging  # noqa: PLC0415
        from app.llm.parser import (  # noqa: PLC0415
            parse_llm_response,
            LLMParseError,
            RETRY_INSTRUCTION,
            SAFE_FALLBACK_VERDICT,
        )
        from app.llm.cache import get_cached_verdict, set_cached_verdict  # noqa: PLC0415

        # ── Step 1: Extract the body string from context ─────────────────
        # context may be an EmailContext dataclass or a plain string.
        if isinstance(context, str):
            body_str = context
        elif hasattr(context, "body"):
            body_str = context.body or ""
        else:
            # Last resort: coerce to string so we never crash
            body_str = str(context)

        sanitized_body = sanitize_email_body(body_str)

        # Normalize findings to a list of dicts for cache key + prompt
        if isinstance(findings, dict):
            findings_list: list[dict[str, Any]] = [findings]
        elif isinstance(findings, list):
            findings_list = [f if isinstance(f, dict) else {"raw": str(f)} for f in findings]
        else:
            findings_list = []

        # ── Step 2: Check semantic cache ──────────────────────────────────
        cached = await get_cached_verdict(sanitized_body, findings_list, self.model)
        if cached is not None:
            return cached

        # ── Step 3: Build the user-message prompt ─────────────────────────
        user_message = _build_user_message(sanitized_body, findings_list)

        # Log the prompt (PII-redacted) for audit
        log.debug(
            "anthropic_provider.prompt_built",
            extra={
                "prompt_preview": redact_pii_for_logging(user_message)[:300],
                "model": self.model,
                "prompt_version": _PROMPT_VERSION,
            },
        )

        # ── Step 4: Call Claude (with 1 retry on parse failure) ───────────
        messages: list[dict[str, str]] = [{"role": "user", "content": user_message}]

        for attempt in range(2):  # attempt 0 = first call, attempt 1 = retry
            try:
                raw_response = await self._call_claude(messages)
            except Exception as exc:  # noqa: BLE001
                log.error(
                    "anthropic_provider.api_error",
                    extra={"attempt": attempt, "error": str(exc)[:300]},
                    exc_info=True,
                )
                return dict(SAFE_FALLBACK_VERDICT)

            # ── Step 5: Parse and validate ────────────────────────────────
            try:
                verdict = parse_llm_response(raw_response)
                break  # Success — exit retry loop
            except LLMParseError as parse_exc:
                log.warning(
                    "anthropic_provider.parse_error",
                    extra={
                        "attempt": attempt,
                        "error": str(parse_exc)[:300],
                        "raw_preview": raw_response[:200],
                    },
                )
                if attempt == 0:
                    # Append the corrective instruction and retry
                    messages.append({"role": "assistant", "content": raw_response})
                    messages.append({"role": "user", "content": RETRY_INSTRUCTION})
                    log.info("anthropic_provider.retrying_with_correction")
                else:
                    # Both attempts failed — return safe fallback
                    log.error(
                        "anthropic_provider.parse_failed_after_retry",
                        extra={"error": str(parse_exc)[:300]},
                    )
                    return dict(SAFE_FALLBACK_VERDICT)
        else:
            # Loop exhausted without break (should not happen, but be safe)
            return dict(SAFE_FALLBACK_VERDICT)

        # ── Step 6: Store in cache ────────────────────────────────────────
        await set_cached_verdict(sanitized_body, findings_list, self.model, verdict)

        log.info(
            "anthropic_provider.verdict_produced",
            extra={
                "verdict": verdict.get("verdict"),
                "semantic_score": verdict.get("semantic_score"),
                "confidence": verdict.get("confidence"),
                "model": self.model,
                "prompt_version": _PROMPT_VERSION,
            },
        )

        return verdict

    # ── Legacy method (kept for backward compatibility) ───────────────────

    async def analyze(self, prompt: str) -> str:
        """Legacy method: send a raw prompt and return the raw text response.

        Prefer ``analyze_semantic()`` for new code.
        """
        return await self._call_claude([{"role": "user", "content": prompt}])

    # ── Private helpers ───────────────────────────────────────────────────

    async def _call_claude(self, messages: list[dict[str, str]]) -> str:
        """Make a single API call to Claude and return the raw text response."""
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            system=self._system_prompt,
            messages=messages,
        )
        return response.content[0].text


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------


def _build_user_message(
    sanitized_body: str,
    findings: list[dict[str, Any]],
) -> str:
    """Build the structured user-message envelope as specified in system.md.

    Format:
        <DETERMINISTIC_EVIDENCE>...</DETERMINISTIC_EVIDENCE>
        <EMAIL_METADATA>...</EMAIL_METADATA>
        <UNTRUSTED_EMAIL>...</UNTRUSTED_EMAIL>
    """
    findings_json = json.dumps(findings, indent=2, ensure_ascii=False)

    return (
        f"<DETERMINISTIC_EVIDENCE>\n"
        f"{findings_json}\n"
        f"</DETERMINISTIC_EVIDENCE>\n\n"
        f"<EMAIL_METADATA>\n"
        f"(metadata not separately provided — see findings above)\n"
        f"</EMAIL_METADATA>\n\n"
        f"<UNTRUSTED_EMAIL>\n"
        f"{sanitized_body}\n"
        f"</UNTRUSTED_EMAIL>"
    )
