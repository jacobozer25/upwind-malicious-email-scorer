"""
backend/app/llm/client.py
--------------------------
LLM provider port — provider-agnostic factory.

Returns a no-op provider when ``llm_provider`` is ``"none"`` (the default
for local dev without API keys). The no-op provider always raises so the
use case falls back to deterministic-only mode.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


class _NoOpLLMProvider:
    """A provider that always raises, triggering the deterministic-only fallback."""

    async def healthcheck(self) -> None:
        log.info(
            "llm.provider_noop",
            extra={"detail": "LLM provider is set to 'none'. Semantic analysis disabled."},
        )

    async def analyze(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(
            "LLM provider is set to 'none'. "
            "Set LLM_PROVIDER=openai or LLM_PROVIDER=anthropic and provide an API key."
        )


def get_llm_provider(settings: Any) -> Any:
    """Return the configured LLM provider instance.

    Parameters
    ----------
    settings:
        The application settings object. Must have ``llm_provider``,
        ``llm_model``, ``llm_timeout_seconds``, ``llm_max_retries``,
        ``openai_api_key``, and ``anthropic_api_key`` attributes.

    Returns
    -------
    Any
        An object implementing ``healthcheck()`` and ``analyze()``.
    """
    provider_name: str = getattr(settings, "llm_provider", "none")

    if provider_name == "none" or not provider_name:
        log.warning(
            "llm.provider_disabled",
            extra={
                "detail": (
                    "LLM_PROVIDER is 'none'. Semantic analysis will be skipped. "
                    "Set LLM_PROVIDER=openai or LLM_PROVIDER=anthropic to enable it."
                )
            },
        )
        return _NoOpLLMProvider()

    if provider_name == "openai":
        try:
            from app.llm.providers.openai_provider import OpenAIProvider  # noqa: PLC0415
            return OpenAIProvider(settings)
        except ImportError as exc:
            log.warning(
                "llm.openai_import_failed",
                extra={"error": str(exc)},
            )
            return _NoOpLLMProvider()

    if provider_name == "anthropic":
        try:
            from app.llm.providers.anthropic_provider import AnthropicProvider  # noqa: PLC0415
            return AnthropicProvider(settings)
        except ImportError as exc:
            log.warning(
                "llm.anthropic_import_failed",
                extra={"error": str(exc)},
            )
            return _NoOpLLMProvider()

    log.warning(
        "llm.unknown_provider",
        extra={"provider": provider_name},
    )
    return _NoOpLLMProvider()
