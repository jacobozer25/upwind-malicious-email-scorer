"""
backend/app/core/security.py
----------------------------
Google ID Token (JWT) verification for the Malicious Email Scorer backend.

Every request from the Gmail Add-on must carry a Google ID token issued by
Apps Script via ``ScriptApp.getIdentityToken()``. This module verifies that
token before any analysis work begins.

Design decisions
================
* We use ``google-auth`` (the official Google library) rather than a generic
  JWT library. It handles JWKS rotation, clock-skew tolerance, and the
  Google-specific claim set automatically.
* All verification failures collapse to a single ``invalid_token`` error code.
  We deliberately do NOT distinguish "expired" from "bad signature" from
  "wrong audience" — an attacker must not be able to probe the validator via
  error messages.
* The ``Caller`` dataclass is the only thing that crosses the security
  boundary into the rest of the application. It carries only the opaque
  ``sub`` (used for rate-limiting) and the ``email`` (used for allowlist
  checks). No raw JWT claims leak further.
* The module is synchronous internally (``google-auth`` is sync) but wrapped
  in an ``async def`` FastAPI dependency so it composes cleanly with other
  async dependencies.

Audience & issuer rules
=======================
* ``aud``  — must equal ``settings.google_audience``.  Set this to your
  backend's public URL (e.g. ``https://api.example.com``) or to the
  Apps Script deployment ID, depending on how you configure
  ``ScriptApp.getIdentityToken()``.
* ``iss``  — must be one of the two canonical Google issuer strings:
  ``"accounts.google.com"`` or ``"https://accounts.google.com"``.
  Google has historically used both; we accept either.
* ``exp``  — verified by ``google-auth`` automatically; we add an explicit
  check as a belt-and-suspenders measure.
* ``email_verified`` — must be ``True``. Unverified Google accounts are
  rejected even if the signature is valid.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Header, HTTPException, status

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Accepted Google issuer strings (both are in active use by Google).
# ---------------------------------------------------------------------------
_VALID_ISSUERS: frozenset[str] = frozenset(
    {"accounts.google.com", "https://accounts.google.com"}
)

# ---------------------------------------------------------------------------
# Domain model: the verified caller identity.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Caller:
    """Verified identity extracted from a Google ID token.

    Attributes
    ----------
    sub:
        The stable, opaque Google user ID (``sub`` claim). Used as the
        rate-limit key — it never changes even if the user changes their
        email address.
    email:
        The caller's Google account email. Used for allowlist checks when
        ``settings.allowed_caller_emails`` is non-empty.
    """

    sub: str
    email: str


# ---------------------------------------------------------------------------
# Token verification helper (pure function — easy to unit-test).
# ---------------------------------------------------------------------------


def verify_google_id_token(
    token: str,
    *,
    audience: str,
    allowed_emails: list[str] | None = None,
) -> Caller:
    """Verify a Google ID token and return the verified ``Caller``.

    Parameters
    ----------
    token:
        The raw JWT string (without the ``Bearer `` prefix).
    audience:
        The expected ``aud`` claim value.  Must match exactly.
    allowed_emails:
        Optional allowlist of permitted caller email addresses.  Pass an
        empty list or ``None`` to allow any verified Google identity.

    Returns
    -------
    Caller
        The verified caller identity.

    Raises
    ------
    HTTPException(401)
        On any verification failure.  The detail string is a stable,
        machine-readable code — never a raw exception message.
    """
    # ── Import lazily so the module can be imported in test environments
    # ── that don't have google-auth installed (they mock this function).
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "google-auth is required: pip install google-auth"
        ) from exc

    # ── Verify signature, audience, and expiry via the official library. ──
    try:
        claims: dict[str, Any] = google_id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            audience=audience,
        )
    except ValueError:
        # google-auth raises ValueError for: bad signature, wrong audience,
        # expired token, malformed JWT, unknown key ID, etc.
        # We collapse all of these to a single opaque error code.
        log.warning("auth.token_verification_failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_token",
        )

    # ── Belt-and-suspenders: explicit issuer check. ───────────────────────
    # google-auth already validates the issuer, but we re-check here so
    # that any future library change that relaxes issuer validation does
    # not silently open a hole.
    if claims.get("iss") not in _VALID_ISSUERS:
        log.warning(
            "auth.invalid_issuer",
            extra={"iss": claims.get("iss")},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_token",
        )

    # ── Belt-and-suspenders: explicit expiry check. ───────────────────────
    if claims.get("exp", 0) < time.time():
        log.warning("auth.token_expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_token",
        )

    # ── Require a verified email address. ────────────────────────────────
    if not claims.get("email_verified", False):
        log.warning("auth.email_not_verified")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_token",
        )

    email: str = claims.get("email", "")
    sub: str = claims.get("sub", "")

    if not sub:
        log.warning("auth.missing_sub_claim")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_token",
        )

    # ── Optional email allowlist. ─────────────────────────────────────────
    if allowed_emails and email not in allowed_emails:
        # Log at INFO (not WARNING) — this is expected in multi-tenant
        # deployments where the allowlist is intentionally restrictive.
        log.info("auth.caller_not_in_allowlist")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_token",
        )

    log.debug("auth.token_verified", extra={"sub": sub})
    return Caller(sub=sub, email=email)


# ---------------------------------------------------------------------------
# FastAPI dependency: authenticated_caller
# ---------------------------------------------------------------------------


async def authenticated_caller(
    authorization: str | None = Header(default=None),
) -> Caller:
    """FastAPI dependency that extracts and verifies the Google ID token.

    Usage
    -----
    ::

        @router.post("/analyze")
        async def analyze(caller: Caller = Depends(authenticated_caller)):
            ...

    The dependency reads ``settings`` via ``get_settings()`` so it always
    uses the live configuration (including any test overrides injected via
    ``app.state.settings``).

    Raises
    ------
    HTTPException(401)
        If the ``Authorization`` header is absent, malformed, or carries an
        invalid/expired token.
    """
    # Avoid circular import: settings lives in app.config which imports
    # nothing from app.core.
    from app.config import get_settings  # noqa: PLC0415

    settings = get_settings()

    # ── Require a Bearer token. ───────────────────────────────────────────
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing_token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing_token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return verify_google_id_token(
        token,
        audience=settings.google_audience,
        allowed_emails=list(settings.allowed_caller_emails)
        if settings.allowed_caller_emails
        else None,
    )
