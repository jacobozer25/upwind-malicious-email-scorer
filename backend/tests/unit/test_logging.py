"""
tests/unit/test_logging.py
---------------------------
Unit tests for the PII redaction logic in ``app.core.logging``.

These tests verify that the redaction functions correctly scrub PII from
log event dicts *before* they are serialised. They test the pure helper
functions directly — no structlog configuration is needed.

Test categories
===============
* Email address redaction
* Phone number redaction
* SSN redaction
* IPv4 partial masking
* Secret field name redaction (by key)
* Nested dict redaction
* List/tuple redaction
* The ``pii_redactor_processor`` structlog processor
* Non-PII strings are left unchanged
"""
from __future__ import annotations

import pytest

from app.core.logging import (
    _redact_string,
    _redact_value,
    pii_redactor_processor,
)

_PII = "[PII_REDACTED]"
_SECRET = "[REDACTED]"


# ---------------------------------------------------------------------------
# _redact_string tests
# ---------------------------------------------------------------------------


class TestRedactString:
    def test_email_is_redacted(self):
        result = _redact_string("Contact us at user@example.com for help.")
        assert "user@example.com" not in result
        assert _PII in result

    def test_multiple_emails_are_redacted(self):
        result = _redact_string("From: alice@corp.com To: bob@corp.com")
        assert "alice@corp.com" not in result
        assert "bob@corp.com" not in result
        assert result.count(_PII) == 2

    def test_phone_us_format_is_redacted(self):
        result = _redact_string("Call us at 555-123-4567 for support.")
        assert "555-123-4567" not in result
        assert _PII in result

    def test_phone_with_country_code_is_redacted(self):
        result = _redact_string("International: +1-555-987-6543")
        assert "+1-555-987-6543" not in result
        assert _PII in result

    def test_ssn_is_redacted(self):
        result = _redact_string("SSN: 123-45-6789 on file.")
        assert "123-45-6789" not in result
        assert _PII in result

    def test_ipv4_last_octet_is_masked(self):
        result = _redact_string("Request from 192.168.1.100")
        assert "192.168.1.100" not in result
        assert "192.168.1.[REDACTED]" in result

    def test_non_pii_string_is_unchanged(self):
        text = "This is a normal log message with no PII."
        assert _redact_string(text) == text

    def test_empty_string_is_unchanged(self):
        assert _redact_string("") == ""

    def test_email_in_url_is_redacted(self):
        result = _redact_string("https://example.com/reset?email=user@test.com")
        assert "user@test.com" not in result

    def test_mixed_pii_types_all_redacted(self):
        text = "User alice@corp.com called from 555-111-2222 with SSN 987-65-4321"
        result = _redact_string(text)
        assert "alice@corp.com" not in result
        assert "555-111-2222" not in result
        assert "987-65-4321" not in result


# ---------------------------------------------------------------------------
# _redact_value tests
# ---------------------------------------------------------------------------


class TestRedactValue:
    def test_secret_key_name_redacts_value(self):
        """Fields with secret-sounding names are redacted regardless of value."""
        assert _redact_value("api_key", "sk-abc123") == _SECRET
        assert _redact_value("token", "eyJhbGciOiJSUzI1NiJ9") == _SECRET
        assert _redact_value("password", "hunter2") == _SECRET
        assert _redact_value("Authorization", "Bearer abc") == _SECRET
        assert _redact_value("secret", "my-secret") == _SECRET

    def test_non_secret_key_with_pii_value_redacts_pii(self):
        """Non-secret key with PII value → PII is redacted from the value."""
        result = _redact_value("message", "Sent to user@example.com")
        assert "user@example.com" not in result
        assert _PII in result

    def test_non_secret_key_with_clean_value_unchanged(self):
        """Non-secret key with clean value → unchanged."""
        assert _redact_value("event", "request.received") == "request.received"

    def test_nested_dict_is_recursively_redacted(self):
        """Nested dicts are recursively processed."""
        data = {
            "user": {"email": "alice@corp.com", "name": "Alice"},
            "api_key": "sk-secret",
        }
        result = _redact_value("data", data)
        assert result["user"]["email"] == _PII
        assert result["user"]["name"] == "Alice"
        assert result["api_key"] == _SECRET

    def test_list_elements_are_redacted(self):
        """List elements containing PII are redacted."""
        data = ["alice@corp.com", "normal text", "bob@corp.com"]
        result = _redact_value("recipients", data)
        assert result[0] == _PII
        assert result[1] == "normal text"
        assert result[2] == _PII

    def test_tuple_elements_are_redacted(self):
        """Tuple elements containing PII are redacted; type is preserved."""
        data = ("alice@corp.com", "normal")
        result = _redact_value("pair", data)
        assert isinstance(result, tuple)
        assert result[0] == _PII
        assert result[1] == "normal"

    def test_integer_value_is_unchanged(self):
        """Non-string, non-container values are passed through unchanged."""
        assert _redact_value("count", 42) == 42

    def test_none_value_is_unchanged(self):
        assert _redact_value("optional", None) is None

    def test_boolean_value_is_unchanged(self):
        assert _redact_value("flag", True) is True

    def test_key_case_insensitive_secret_detection(self):
        """Secret key detection is case-insensitive."""
        assert _redact_value("API_KEY", "value") == _SECRET
        assert _redact_value("AccessToken", "value") == _SECRET
        assert _redact_value("AUTHORIZATION", "value") == _SECRET


# ---------------------------------------------------------------------------
# pii_redactor_processor tests
# ---------------------------------------------------------------------------


class TestPIIRedactorProcessor:
    def _run(self, event_dict: dict) -> dict:
        """Run the processor with dummy logger/method args."""
        return pii_redactor_processor(None, "info", event_dict)

    def test_event_message_pii_is_redacted(self):
        event_dict = {"event": "User alice@corp.com logged in"}
        result = self._run(event_dict)
        assert "alice@corp.com" not in result["event"]
        assert _PII in result["event"]

    def test_extra_field_pii_is_redacted(self):
        event_dict = {
            "event": "request.received",
            "from_address": "attacker@evil.com",
        }
        result = self._run(event_dict)
        assert "attacker@evil.com" not in result["from_address"]
        assert _PII in result["from_address"]

    def test_secret_field_is_redacted(self):
        event_dict = {
            "event": "auth.attempt",
            "token": "eyJhbGciOiJSUzI1NiJ9.payload.sig",
        }
        result = self._run(event_dict)
        assert result["token"] == _SECRET

    def test_clean_event_dict_is_unchanged(self):
        event_dict = {
            "event": "startup.complete",
            "environment": "prod",
            "version": "1.0.0",
        }
        result = self._run(event_dict)
        assert result["event"] == "startup.complete"
        assert result["environment"] == "prod"
        assert result["version"] == "1.0.0"

    def test_event_key_is_not_treated_as_secret(self):
        """The 'event' key itself must not be redacted as a secret field."""
        event_dict = {"event": "verdict.produced", "score": 42}
        result = self._run(event_dict)
        assert result["event"] == "verdict.produced"

    def test_nested_pii_in_extra_field_is_redacted(self):
        event_dict = {
            "event": "email.analyzed",
            "metadata": {"from": "user@example.com", "subject": "Hello"},
        }
        result = self._run(event_dict)
        assert result["metadata"]["from"] == _PII
        assert result["metadata"]["subject"] == "Hello"

    def test_processor_returns_dict(self):
        """The processor must always return a dict."""
        result = self._run({"event": "test"})
        assert isinstance(result, dict)

    def test_processor_does_not_raise_on_empty_dict(self):
        """Empty event dict should not raise."""
        result = self._run({})
        assert isinstance(result, dict)
