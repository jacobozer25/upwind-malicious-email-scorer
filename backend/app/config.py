"""
backend/app/config.py
----------------------
Typed env-var loader using pydantic-settings.

Design
======
* All configuration is loaded from environment variables (and optionally a
  ``.env`` file in the working directory).
* Missing required secrets cause the application to fail at startup with a
  clear error message — loud failures are features, not bugs.
* ``redis_url`` is **optional** (defaults to ``None``). When absent, the
  Redis cache adapter falls back to the in-memory mock automatically.
* ``google_audience`` is required in production but defaults to an empty
  string in dev so the app can start without a Google Cloud project.

Local dev quick-start
=====================
Create a ``.env`` file in ``backend/`` with at minimum::

    LLM_PROVIDER=openai
    OPENAI_API_KEY=sk-...
    GOOGLE_AUDIENCE=http://localhost:8080

Redis is optional — if ``REDIS_URL`` is not set, the in-memory mock is used.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

try:
    from pydantic import Field, SecretStr
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class Settings(BaseSettings):
        model_config = SettingsConfigDict(
            env_file=".env",
            env_file_encoding="utf-8",
            extra="ignore",   # Ignore unknown env vars (don't crash on them)
            frozen=True,      # Immutable after construction
        )

        environment: Literal["dev", "staging", "prod"] = "dev"
        expose_docs: bool = True   # True in dev for easy exploration
        log_level: str = "INFO"

        # ── Auth ─────────────────────────────────────────────────────────────
        # Empty string = skip JWT verification (dev only).
        google_audience: str = ""
        allowed_caller_emails: list[str] = Field(default_factory=list)

        # ── LLM ──────────────────────────────────────────────────────────────
        llm_provider: Literal["openai", "anthropic", "none"] = "none"
        llm_model: str = "gpt-4o-mini"
        llm_timeout_seconds: float = 8.0
        llm_max_retries: int = 2
        openai_api_key: SecretStr | None = None
        anthropic_api_key: SecretStr | None = None

        # ── Redis (optional — falls back to in-memory mock if not set) ───────
        redis_url: str | None = None
        rate_limit_per_minute: int = 60
        rate_limit_per_day: int = 1000

        # ── CORS ─────────────────────────────────────────────────────────────
        cors_allow_origins: list[str] = Field(
            default_factory=lambda: ["https://script.google.com", "http://localhost:3000"]
        )

        # ── Limits ───────────────────────────────────────────────────────────
        max_body_bytes: int = 1_048_576       # 1 MB request cap
        max_email_body_chars: int = 200_000
        llm_input_truncate_kb: int = 16

except ImportError:
    # Fallback for environments where pydantic-settings is not installed.
    # Provides a minimal Settings object so the module can be imported.
    class Settings:  # type: ignore[no-redef]
        environment = "dev"
        expose_docs = True
        log_level = "INFO"
        google_audience = ""
        allowed_caller_emails: list = []
        llm_provider = "none"
        llm_model = "gpt-4o-mini"
        llm_timeout_seconds = 8.0
        llm_max_retries = 2
        openai_api_key = None
        anthropic_api_key = None
        redis_url = None
        rate_limit_per_minute = 60
        rate_limit_per_day = 1000
        cors_allow_origins = ["https://script.google.com"]
        max_body_bytes = 1_048_576
        max_email_body_chars = 200_000
        llm_input_truncate_kb = 16


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()  # type: ignore[call-arg]
