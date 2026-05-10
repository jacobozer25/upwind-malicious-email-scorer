"""
backend/app/core/logging.py
----------------------------
Structured logging configuration with PII redaction.

This module is the **single entry point** for logging setup. It must be
called exactly once, at application startup (in ``main.py``'s lifespan
handler), before any other log output is produced.

Features
========
* **Structured JSON output** via ``structlog``. Every log line is a JSON
  object with consistent fields: ``timestamp``, ``level``, ``logger``,
  ``event``, ``request_id``, and any extra fields passed by the caller.
* **PII redaction** — a custom processor scrubs emails, phone numbers, and
  other PII patterns from log messages and extra fields *before* they are
  serialised. This ensures that even if a developer accidentally logs a
  request body, PII does not appear in the log stream.
* **Secret scrubbing** — fields whose names match ``*token*``, ``*key*``,
  ``*secret*``, ``*password*``, or ``Authorization`` are replaced with
  ``"[REDACTED]"`` regardless of their value.
* **Development mode** — when ``settings.environment == "dev"``, logs are
  rendered as coloured, human-readable console output instead of JSON.
* **Standard-library bridge** — ``logging.basicConfig`` is NOT called.
  Instead, we install a ``structlog``-aware handler on the root logger so
  that third-party libraries (uvicorn, httpx, google-auth) also emit
  structured JSON.

PII patterns redacted
=====================
* Email addresses: ``user@example.com``
* Phone numbers: ``+1-555-123-4567``, ``(555) 123-4567``, ``5551234567``
* US SSNs: ``123-45-6789``
* Credit card numbers (16-digit sequences): ``4111111111111111``
* IPv4 addresses in log *values* (not keys) are partially masked:
  ``192.168.1.100`` → ``192.168.1.[REDACTED]``

Design notes
============
* Redaction happens in a ``structlog`` processor, not in a logging
  ``Filter``. This means it runs on the structured event dict *before*
  serialisation, so it catches PII in both the message string and in
  extra keyword arguments.
* The redaction regex is compiled once at module load time.
* We use ``structlog.stdlib.ProcessorFormatter`` as the bridge between
  ``structlog`` and the standard ``logging`` module. This means all
  ``logging.getLogger(__name__)`` calls in the codebase automatically
  benefit from structured output and PII redaction.
"""
from __future__ import annotations

import logging
import logging.config
import re
import sys
from typing import Any

import structlog

# ---------------------------------------------------------------------------
# PII redaction patterns
# ---------------------------------------------------------------------------

# Email addresses.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Phone numbers (US-centric but catches most international formats).
_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+?1[\s\-.]?)?"
    r"(?:\(?\d{3}\)?[\s\-.]?)"
    r"\d{3}[\s\-.]?\d{4}"
    r"(?!\d)"
)

# US Social Security Numbers.
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Credit card numbers (13–16 digit sequences, optionally space/dash separated).
_CC_RE = re.compile(r"\b(?:\d[ \-]?){13,16}\b")

# IPv4 addresses — mask the last octet.
_IPV4_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b"
)

# Secret field name patterns (case-insensitive key matching).
_SECRET_KEY_RE = re.compile(
    r"(?i)(token|key|secret|password|passwd|credential|authorization|auth)",
)

# Replacement strings.
_PII_REPLACEMENT = "[PII_REDACTED]"
_SECRET_REPLACEMENT = "[REDACTED]"
_IP_REPLACEMENT = r"\1.[REDACTED]"


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------


def _redact_string(value: str) -> str:
    """Apply all PII redaction patterns to a string value."""
    value = _EMAIL_RE.sub(_PII_REPLACEMENT, value)
    value = _PHONE_RE.sub(_PII_REPLACEMENT, value)
    value = _SSN_RE.sub(_PII_REPLACEMENT, value)
    value = _CC_RE.sub(_PII_REPLACEMENT, value)
    value = _IPV4_RE.sub(_IP_REPLACEMENT, value)
    return value


def _redact_value(key: str, value: Any) -> Any:
    """Redact a single key-value pair from the event dict."""
    # Redact secret fields by key name.
    if isinstance(key, str) and _SECRET_KEY_RE.search(key):
        return _SECRET_REPLACEMENT

    # Redact PII from string values.
    if isinstance(value, str):
        return _redact_string(value)

    # Recursively redact nested dicts.
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}

    # Redact PII from list/tuple elements.
    if isinstance(value, (list, tuple)):
        redacted = [_redact_value("", item) for item in value]
        return type(value)(redacted)

    return value


# ---------------------------------------------------------------------------
# structlog processor: PII redactor
# ---------------------------------------------------------------------------


def pii_redactor_processor(
    logger: Any,
    method: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """structlog processor that redacts PII from the event dict.

    This processor runs on every log event *before* serialisation. It:
    1. Redacts PII from the ``event`` (message) string.
    2. Redacts PII and secrets from all other fields in the event dict.

    Parameters
    ----------
    logger:
        The bound logger (unused).
    method:
        The log method name (unused).
    event_dict:
        The mutable event dict to process.

    Returns
    -------
    dict[str, Any]
        The event dict with PII redacted.
    """
    # Redact the main event message.
    if "event" in event_dict and isinstance(event_dict["event"], str):
        event_dict["event"] = _redact_string(event_dict["event"])

    # Redact all other fields.
    for key in list(event_dict.keys()):
        if key == "event":
            continue
        event_dict[key] = _redact_value(key, event_dict[key])

    return event_dict


# ---------------------------------------------------------------------------
# structlog processor: add log level as a string field
# ---------------------------------------------------------------------------


def add_log_level_processor(
    logger: Any,
    method: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add the log level as a string field ``level`` to the event dict."""
    event_dict["level"] = method.upper()
    return event_dict


# ---------------------------------------------------------------------------
# Main configuration function
# ---------------------------------------------------------------------------


def configure_logging(settings: Any | None = None) -> None:
    """Configure structlog and the standard-library logging bridge.

    Call this exactly once at application startup, before any log output.

    Parameters
    ----------
    settings:
        The application settings object.  Used to determine the
        environment (``dev`` vs ``prod``) and log level.  If ``None``,
        defaults to ``INFO`` level and JSON output.
    """
    environment = getattr(settings, "environment", "prod")
    log_level_name = getattr(settings, "log_level", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    # ── Shared processors (run on every log event) ─────────────────────────
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        add_log_level_processor,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        pii_redactor_processor,  # ← PII redaction runs here, before serialisation
    ]

    if environment == "dev":
        # ── Development: coloured, human-readable console output ──────────
        renderer: Any = structlog.dev.ConsoleRenderer(colors=True)
    else:
        # ── Production: JSON output ────────────────────────────────────────
        renderer = structlog.processors.JSONRenderer()

    # ── Configure structlog ────────────────────────────────────────────────
    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # ── Configure the standard-library logging bridge ─────────────────────
    # This ensures that third-party libraries (uvicorn, httpx, google-auth)
    # also emit structured, PII-redacted output.
    formatter = structlog.stdlib.ProcessorFormatter(
        # These processors run on stdlib log records *after* structlog's
        # shared processors have already run.
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Silence noisy third-party loggers in production.
    if environment != "dev":
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Emit a startup confirmation (this will be the first structured log line).
    log = structlog.get_logger(__name__)
    log.info(
        "logging.configured",
        environment=environment,
        log_level=log_level_name,
        pii_redaction="enabled",
    )


# ---------------------------------------------------------------------------
# Convenience: get a structlog logger (preferred over logging.getLogger)
# ---------------------------------------------------------------------------


def get_logger(name: str) -> Any:
    """Return a structlog bound logger for the given module name.

    Usage::

        from app.core.logging import get_logger
        log = get_logger(__name__)
        log.info("my.event", key="value")

    This is preferred over ``logging.getLogger(__name__)`` because it
    returns a structlog logger that supports keyword arguments natively.
    """
    return structlog.get_logger(name)
