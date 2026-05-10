"""
backend/app/api/v1/endpoints/analyze.py
-----------------------------------------
``POST /v1/analyze`` — the primary email-scoring endpoint.

Request flow
============
1. FastAPI validates the request body against :class:`~app.schemas.request.AnalyzeEmailRequest`
   (Pydantic strict validation, 1 MB body cap, email format check).
2. The handler converts the request to an :class:`~app.domain.models.EmailContext`
   domain object.
3. The :class:`~app.services.email_analyzer.AnalyzeEmailUseCase` is injected
   via FastAPI's ``Depends()`` mechanism and ``execute()`` is awaited.
4. The resulting :class:`~app.services.email_analyzer.EmailVerdict` is
   converted to an :class:`~app.schemas.response.AnalyzeEmailResponse` and
   returned as JSON.

Resilience contract
===================
* The endpoint **always returns HTTP 200** as long as the request is valid.
  LLM failures, timeouts, and reputation-feed outages are handled inside the
  use case and surfaced via ``llm_available: false`` + ``semantic_warning``
  in the response body.
* HTTP 422 is returned by FastAPI automatically on schema validation failure.
* HTTP 401 is returned by the Google ID-token verifier middleware if the
  ``Authorization`` header is missing or invalid.
* HTTP 429 is returned by the rate-limiter middleware if the per-user quota
  is exceeded.

Logging
=======
Request metadata (sender domain, subject length, attachment count) is logged
at INFO level for auditability.  The full body and the sender's local-part
are **never** logged (PII protection).

Security notes
==============
* The ``Authorization`` header is verified by
  :func:`~app.core.security.verify_google_id_token` before this handler runs.
* The body is treated as untrusted input throughout the pipeline.
* No PII is logged — the structlog PII redactor strips email addresses,
  tokens, and phone numbers from all log records.
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.domain.models import EmailContext
from app.schemas.request import AnalyzeEmailRequest
from app.schemas.response import AnalyzeEmailResponse
from app.services.email_analyzer import AnalyzeEmailUseCase, get_use_case

log = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/analyze",
    response_model=AnalyzeEmailResponse,
    summary="Analyze an email for malicious signals",
    description=(
        "Runs the full deterministic + LLM pipeline on the supplied email "
        "and returns a risk score, risk level, and detailed findings. "
        "Always returns HTTP 200 — LLM failures are surfaced in the response "
        "body via `llm_available` and `semantic_warning`."
    ),
    responses={
        200: {"description": "Analysis complete (LLM may have been gated or failed)."},
        422: {"description": "Request validation failed (invalid email, body too large, etc.)."},
        401: {"description": "Missing or invalid Google ID token."},
        429: {"description": "Rate limit exceeded."},
    },
)
async def analyze_email(
    request: Request,
    body: AnalyzeEmailRequest,
    use_case: Annotated[AnalyzeEmailUseCase, Depends(get_use_case)],
) -> AnalyzeEmailResponse:
    """Analyze an email for malicious signals.

    Args:
        request: The raw FastAPI request (used for request-id logging).
        body: The validated :class:`~app.schemas.request.AnalyzeEmailRequest`.
        use_case: The injected :class:`~app.services.email_analyzer.AnalyzeEmailUseCase`.

    Returns:
        An :class:`~app.schemas.response.AnalyzeEmailResponse` with the full
        verdict.  Always HTTP 200.
    """
    request_id: str = request.headers.get("X-Request-ID", "unknown")

    # ── Log request metadata (no PII, no body content). ──────────────────
    sender_domain = body.from_address.split("@")[-1] if "@" in body.from_address else "unknown"
    log.info(
        "analyze.request_received",
        extra={
            "request_id": request_id,
            "sender_domain": sender_domain,
            "subject_length": len(body.subject),
            "body_length": len(body.body),
            "header_count": len(body.headers),
            "attachment_count": len(body.attachment_metadata),
        },
    )

    # ── Build domain object. ──────────────────────────────────────────────
    context = EmailContext(
        sender=body.from_address,
        recipient=_extract_recipient(body.headers),
        subject=body.subject,
        body=body.body,
        headers=body.headers,
        attachment_metadata=list(body.attachment_metadata),  # type: ignore[arg-type]
    )

    # ── Run the pipeline. ─────────────────────────────────────────────────
    verdict = await use_case.execute(context)

    # ── Log verdict summary. ──────────────────────────────────────────────
    log.info(
        "analyze.verdict_produced",
        extra={
            "request_id": request_id,
            "final_score": verdict.final_score,
            "risk_level": verdict.risk_level.value,
            "llm_available": verdict.llm_available,
            "llm_gated": verdict.llm_gated,
            "finding_count": len(verdict.deterministic_findings),
        },
    )

    # ── Convert to response DTO and return. ───────────────────────────────
    return AnalyzeEmailResponse.from_verdict(verdict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_recipient(headers: dict[str, str]) -> str:
    """Extract the primary recipient from the email headers.

    Looks for ``To``, ``Delivered-To``, or ``X-Original-To`` headers.
    Returns an empty string if none are found.
    """
    for key in ("To", "to", "Delivered-To", "delivered-to", "X-Original-To"):
        value = headers.get(key, "")
        if value:
            # Strip display name if present: "Alice <alice@example.com>" → "alice@example.com"
            if "<" in value and ">" in value:
                return value.split("<")[-1].rstrip(">").strip()
            return value.strip()
    return ""
