"""
tests/unit/test_security.py
-----------------------------
Unit tests for Google ID Token verification in ``app.core.security``.

These tests verify the ``verify_google_id_token`` function in complete
isolation — the ``google.oauth2.id_token.verify_oauth2_token`` call is
mocked so no real network requests are made and no real JWT is needed.

Test categories
===============
* Valid token → returns Caller with correct sub/email
* Invalid token (ValueError from google-auth) → 401
* Wrong issuer → 401
* Expired token (exp in the past) → 401
* Unverified email (email_verified=False) → 401
* Missing sub claim → 401
* Caller not in allowlist → 401
* Empty allowlist → any verified caller is accepted
* Bearer token extraction in ``authenticated_caller`` dependency
"""
from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.core.security import Caller, verify_google_id_token

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AUDIENCE = "https://api.example.com"
_VALID_CLAIMS: dict[str, Any] = {
    "iss": "https://accounts.google.com",
    "aud": _AUDIENCE,
    "sub": "1234567890",
    "email": "user@example.com",
    "email_verified": True,
    "exp": int(time.time()) + 3600,  # 1 hour from now
    "iat": int(time.time()) - 60,
}


def _mock_verify(claims: dict[str, Any] | None = None, raises: bool = False):
    """Return a context manager that patches google-auth's verify function."""
    if raises:
        return patch(
            "app.core.security.verify_google_id_token.__wrapped__",
            side_effect=ValueError("bad token"),
        )

    def _patcher(target_claims: dict[str, Any]):
        return patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=target_claims,
        )

    return _patcher(claims or _VALID_CLAIMS)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVerifyGoogleIdToken:
    def test_valid_token_returns_caller(self):
        """A valid token with all required claims returns a Caller."""
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=_VALID_CLAIMS,
        ):
            caller = verify_google_id_token("valid.jwt.token", audience=_AUDIENCE)

        assert isinstance(caller, Caller)
        assert caller.sub == "1234567890"
        assert caller.email == "user@example.com"

    def test_invalid_token_raises_401(self):
        """google-auth raises ValueError → 401 with 'invalid_token'."""
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            side_effect=ValueError("bad signature"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                verify_google_id_token("bad.jwt.token", audience=_AUDIENCE)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "invalid_token"

    def test_wrong_issuer_raises_401(self):
        """Token with unexpected issuer → 401."""
        bad_claims = {**_VALID_CLAIMS, "iss": "https://evil.com"}
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=bad_claims,
        ):
            with pytest.raises(HTTPException) as exc_info:
                verify_google_id_token("token", audience=_AUDIENCE)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "invalid_token"

    def test_accounts_google_com_issuer_accepted(self):
        """Both 'accounts.google.com' and 'https://accounts.google.com' are valid."""
        claims_short_iss = {**_VALID_CLAIMS, "iss": "accounts.google.com"}
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=claims_short_iss,
        ):
            caller = verify_google_id_token("token", audience=_AUDIENCE)

        assert caller.sub == "1234567890"

    def test_expired_token_raises_401(self):
        """Token with exp in the past → 401."""
        expired_claims = {**_VALID_CLAIMS, "exp": int(time.time()) - 3600}
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=expired_claims,
        ):
            with pytest.raises(HTTPException) as exc_info:
                verify_google_id_token("token", audience=_AUDIENCE)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "invalid_token"

    def test_unverified_email_raises_401(self):
        """Token with email_verified=False → 401."""
        unverified_claims = {**_VALID_CLAIMS, "email_verified": False}
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=unverified_claims,
        ):
            with pytest.raises(HTTPException) as exc_info:
                verify_google_id_token("token", audience=_AUDIENCE)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "invalid_token"

    def test_missing_sub_claim_raises_401(self):
        """Token without 'sub' claim → 401."""
        no_sub_claims = {k: v for k, v in _VALID_CLAIMS.items() if k != "sub"}
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=no_sub_claims,
        ):
            with pytest.raises(HTTPException) as exc_info:
                verify_google_id_token("token", audience=_AUDIENCE)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "invalid_token"

    def test_caller_in_allowlist_is_accepted(self):
        """Caller whose email is in the allowlist → accepted."""
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=_VALID_CLAIMS,
        ):
            caller = verify_google_id_token(
                "token",
                audience=_AUDIENCE,
                allowed_emails=["user@example.com", "admin@example.com"],
            )

        assert caller.email == "user@example.com"

    def test_caller_not_in_allowlist_raises_401(self):
        """Caller whose email is NOT in the allowlist → 401."""
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=_VALID_CLAIMS,
        ):
            with pytest.raises(HTTPException) as exc_info:
                verify_google_id_token(
                    "token",
                    audience=_AUDIENCE,
                    allowed_emails=["admin@example.com"],  # user@example.com not here
                )

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "invalid_token"

    def test_empty_allowlist_accepts_any_verified_caller(self):
        """Empty allowlist → any verified Google identity is accepted."""
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=_VALID_CLAIMS,
        ):
            caller = verify_google_id_token(
                "token",
                audience=_AUDIENCE,
                allowed_emails=[],  # Empty list = no restriction
            )

        assert caller.sub == "1234567890"

    def test_none_allowlist_accepts_any_verified_caller(self):
        """None allowlist → any verified Google identity is accepted."""
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=_VALID_CLAIMS,
        ):
            caller = verify_google_id_token(
                "token",
                audience=_AUDIENCE,
                allowed_emails=None,
            )

        assert caller.sub == "1234567890"

    def test_caller_is_frozen_dataclass(self):
        """Caller must be immutable."""
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=_VALID_CLAIMS,
        ):
            caller = verify_google_id_token("token", audience=_AUDIENCE)

        with pytest.raises((AttributeError, TypeError)):
            caller.sub = "mutated"  # type: ignore[misc]

    def test_error_detail_is_opaque(self):
        """All 401 errors use the same opaque detail code — no information leakage."""
        error_scenarios = [
            {**_VALID_CLAIMS, "iss": "https://evil.com"},  # bad issuer
            {**_VALID_CLAIMS, "exp": int(time.time()) - 1},  # expired
            {**_VALID_CLAIMS, "email_verified": False},  # unverified email
        ]
        for bad_claims in error_scenarios:
            with patch(
                "google.oauth2.id_token.verify_oauth2_token",
                return_value=bad_claims,
            ):
                with pytest.raises(HTTPException) as exc_info:
                    verify_google_id_token("token", audience=_AUDIENCE)

            # All failures must use the same opaque error code.
            assert exc_info.value.detail == "invalid_token", (
                f"Expected 'invalid_token' for claims {bad_claims}, "
                f"got '{exc_info.value.detail}'"
            )
