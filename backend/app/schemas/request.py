"""
backend/app/schemas/request.py
--------------------------------
Pydantic request schema for the ``POST /v1/analyze`` endpoint.

Validation rules
================
* ``from_address`` must be a valid email address (Pydantic ``EmailStr``).
* ``body`` is capped at 1 MB (1,048,576 bytes) to prevent oversized payloads
  from reaching the LLM or the deterministic analyzers.
* ``subject`` is capped at 998 characters (RFC 5322 maximum line length).
* ``headers`` values are capped at 8 KB each to prevent header-injection
  attacks from inflating memory usage.
* All string fields use ``strict=False`` (default) so that the JSON parser
  can coerce values normally.

Security notes
==============
* The body is treated as **untrusted input** throughout the pipeline.
  The prompt-injection sanitizer (``app.llm.sanitizer``) wraps it in a
  structural isolation block before it reaches the LLM.
* PII (email addresses, phone numbers) is stripped from logs by the
  structlog PII redactor (``app.core.logging``).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, EmailStr, Field, field_validator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_BODY_BYTES: int = 1 * 1024 * 1024  # 1 MB
_MAX_SUBJECT_LEN: int = 998             # RFC 5322 max line length
_MAX_HEADER_VALUE_LEN: int = 8 * 1024   # 8 KB per header value
_MAX_HEADERS: int = 100                 # Maximum number of headers


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------


class AnalyzeEmailRequest(BaseModel):
    """Request body for ``POST /v1/analyze``.

    Attributes
    ----------
    from_address:
        The RFC 5321 envelope sender address (MAIL FROM).  Must be a valid
        email address.
    subject:
        The decoded email subject line.  Capped at 998 characters.
    body:
        The plain-text (or HTML) body of the email.  Capped at 1 MB.
    headers:
        A mapping of header name → value for all relevant headers.
        Optional — defaults to an empty dict.
    attachment_metadata:
        A list of metadata dicts for each attachment.  Each dict should
        contain at minimum ``filename``, ``mime_type``, and ``size_bytes``.
        Attachment *bytes* must never be sent — only metadata.
    """

    model_config = {"str_strip_whitespace": True}

    from_address: Annotated[
        EmailStr,
        Field(description="Envelope sender address (MAIL FROM). Must be a valid email."),
    ]

    subject: Annotated[
        str,
        Field(
            default="",
            max_length=_MAX_SUBJECT_LEN,
            description=f"Email subject line (max {_MAX_SUBJECT_LEN} characters).",
        ),
    ]

    body: Annotated[
        str,
        Field(
            default="",
            description=f"Email body — plain text or HTML (max {_MAX_BODY_BYTES // 1024} KB).",
        ),
    ]

    headers: Annotated[
        dict[str, str],
        Field(
            default_factory=dict,
            description="Email headers as a flat key→value mapping.",
        ),
    ]

    attachment_metadata: Annotated[
        list[dict[str, object]],
        Field(
            default_factory=list,
            description=(
                "Metadata for each attachment. Each entry must include "
                "'filename', 'mime_type', and 'size_bytes'. "
                "Attachment bytes must NOT be included."
            ),
        ),
    ]

    # ── Validators ────────────────────────────────────────────────────────

    @field_validator("body")
    @classmethod
    def body_size_limit(cls, v: str) -> str:
        """Reject bodies larger than 1 MB (encoded as UTF-8)."""
        if len(v.encode("utf-8")) > _MAX_BODY_BYTES:
            raise ValueError(
                f"Email body exceeds the maximum allowed size of "
                f"{_MAX_BODY_BYTES // 1024} KB."
            )
        return v

    @field_validator("headers")
    @classmethod
    def headers_size_limit(cls, v: dict[str, str]) -> dict[str, str]:
        """Reject header dicts with too many entries or oversized values."""
        if len(v) > _MAX_HEADERS:
            raise ValueError(
                f"Too many headers: {len(v)} (maximum {_MAX_HEADERS})."
            )
        for name, value in v.items():
            if len(value.encode("utf-8")) > _MAX_HEADER_VALUE_LEN:
                raise ValueError(
                    f"Header '{name}' value exceeds the maximum allowed size of "
                    f"{_MAX_HEADER_VALUE_LEN // 1024} KB."
                )
        return v

    @field_validator("attachment_metadata")
    @classmethod
    def attachment_metadata_limit(cls, v: list[dict]) -> list[dict]:
        """Reject attachment lists with more than 50 entries."""
        if len(v) > 50:
            raise ValueError(
                f"Too many attachments: {len(v)} (maximum 50)."
            )
        return v
