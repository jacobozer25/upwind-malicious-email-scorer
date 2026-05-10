"""
backend/app/llm/sanitizer.py
------------------------------
Email body sanitizer — 5-step pipeline that runs before the body reaches
the LLM.

Steps (as specified in system.md "Sanitizer notes")
====================================================
1. Strip zero-width characters (U+200B, U+200C, U+200D, U+FEFF) — common
   injection-obfuscation trick.
2. Normalize Unicode to NFKC, then apply a homograph map for confusables
   (e.g. Cyrillic 'а' → Latin 'a').
3. Neutralize role tokens: replace literal occurrences of ``system:``,
   ``assistant:``, ``</UNTRUSTED_EMAIL>``, and the schema delimiters with
   HTML-entity equivalents so they cannot escape the structural isolation
   block.
4. Hard-truncate to 16 kB (configurable). Tail content is replaced with
   ``[...truncated by sanitizer...]``.
5. Redact obvious PII before logging the prompt for audit (emails, phones,
   SSNs).

The sanitizer is intentionally conservative: it prefers false positives
(over-sanitizing) to false negatives (under-sanitizing).  Any sanitization
that fires is itself a signal of potential injection and is logged.
"""
from __future__ import annotations

import logging
import re
import unicodedata

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Step 1 — zero-width characters to strip
_ZERO_WIDTH_CHARS: frozenset[str] = frozenset(
    "\u200b"  # ZERO WIDTH SPACE
    "\u200c"  # ZERO WIDTH NON-JOINER
    "\u200d"  # ZERO WIDTH JOINER
    "\ufeff"  # ZERO WIDTH NO-BREAK SPACE (BOM)
)

# Step 2 — homograph confusable map (Cyrillic / Greek → Latin lookalikes)
# Extend this map as new confusables are discovered in evals.
_HOMOGRAPH_MAP: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "r",  # р → r
    "\u0441": "c",  # с → c
    "\u0445": "x",  # х → x
    "\u0440": "r",  # р → r
    "\u0456": "i",  # і → i
    # Greek
    "\u03b1": "a",  # α → a
    "\u03b5": "e",  # ε → e
    "\u03bf": "o",  # ο → o
    "\u03c1": "p",  # ρ → p
    "\u03c5": "u",  # υ → u
    # Full-width ASCII (common in East Asian spam)
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
}

# Step 3 — role tokens to neutralize (HTML-entity encode the colon/angle)
_ROLE_TOKEN_REPLACEMENTS: list[tuple[str, str]] = [
    ("system:",             "system&#58;"),
    ("assistant:",          "assistant&#58;"),
    ("</UNTRUSTED_EMAIL>",  "&lt;/UNTRUSTED_EMAIL&gt;"),
    ("<UNTRUSTED_EMAIL>",   "&lt;UNTRUSTED_EMAIL&gt;"),
    ("</DETERMINISTIC_EVIDENCE>", "&lt;/DETERMINISTIC_EVIDENCE&gt;"),
    ("<DETERMINISTIC_EVIDENCE>",  "&lt;DETERMINISTIC_EVIDENCE&gt;"),
    ("</EMAIL_METADATA>",  "&lt;/EMAIL_METADATA&gt;"),
    ("<EMAIL_METADATA>",   "&lt;EMAIL_METADATA&gt;"),
    # Anthropic-specific role tokens
    ("\nHuman:",            "\nHuman&#58;"),
    ("\nAssistant:",        "\nAssistant&#58;"),
]

# Step 4 — default truncation limit (16 kB)
_DEFAULT_MAX_BYTES: int = 16 * 1024
_TRUNCATION_MARKER: str = "\n[...truncated by sanitizer...]"

# Step 5 — PII redaction patterns (for audit logging only)
_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Email addresses
    (re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
     "[EMAIL]"),
    # US phone numbers (various formats)
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
     "[PHONE]"),
    # SSN-like patterns
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
     "[SSN]"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sanitize_email_body(
    body: str,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> str:
    """Run the 5-step sanitization pipeline on an email body.

    Args:
        body: The raw email body text (plain text or lightly stripped HTML).
        max_bytes: Hard truncation limit in bytes (UTF-8 encoded).
            Defaults to 16 kB as specified in system.md.

    Returns:
        The sanitized body string, safe to embed inside the
        ``<UNTRUSTED_EMAIL>`` block of the LLM prompt.
    """
    original_len = len(body)
    mutations: list[str] = []

    # ── Step 1: Strip zero-width characters ──────────────────────────────
    cleaned = "".join(ch for ch in body if ch not in _ZERO_WIDTH_CHARS)
    if len(cleaned) != original_len:
        mutations.append("zero_width_chars_stripped")

    # ── Step 2: Unicode normalization + homograph substitution ───────────
    normalized = unicodedata.normalize("NFKC", cleaned)
    homograph_replaced = "".join(_HOMOGRAPH_MAP.get(ch, ch) for ch in normalized)
    if homograph_replaced != normalized:
        mutations.append("homograph_chars_replaced")

    # ── Step 3: Neutralize role tokens ───────────────────────────────────
    neutralized = homograph_replaced
    for token, replacement in _ROLE_TOKEN_REPLACEMENTS:
        if token in neutralized:
            neutralized = neutralized.replace(token, replacement)
            mutations.append(f"role_token_neutralized:{token!r}")

    # ── Step 4: Hard truncation ───────────────────────────────────────────
    encoded = neutralized.encode("utf-8")
    if len(encoded) > max_bytes:
        # Truncate at a UTF-8 character boundary.
        truncated_bytes = encoded[:max_bytes]
        # Decode with errors='ignore' to handle partial multi-byte chars.
        truncated = truncated_bytes.decode("utf-8", errors="ignore")
        result = truncated + _TRUNCATION_MARKER
        mutations.append(
            f"truncated:{original_len}_chars_to_{max_bytes}_bytes"
        )
    else:
        result = neutralized

    # ── Log mutations (without PII) ───────────────────────────────────────
    if mutations:
        log.warning(
            "sanitizer.mutations_applied",
            extra={
                "mutation_count": len(mutations),
                "mutations": mutations,
                "original_length": original_len,
                "sanitized_length": len(result),
            },
        )
    else:
        log.debug("sanitizer.no_mutations", extra={"body_length": len(result)})

    return result


def redact_pii_for_logging(text: str) -> str:
    """Redact obvious PII from a string before writing it to audit logs.

    This is Step 5 of the sanitization pipeline.  It is applied to the
    *full prompt* (not just the body) before logging, so that email
    addresses, phone numbers, and SSNs are never written to log storage.

    Args:
        text: The text to redact (e.g. the full LLM prompt string).

    Returns:
        The text with PII replaced by placeholder tokens.
    """
    redacted = text
    for pattern, placeholder in _PII_PATTERNS:
        redacted = pattern.sub(placeholder, redacted)
    return redacted
