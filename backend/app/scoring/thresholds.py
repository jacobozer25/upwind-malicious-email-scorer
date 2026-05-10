"""
backend/app/scoring/thresholds.py
-----------------------------------
Score thresholds, risk-level bands, and LLM gating constants for the
malicious email scorer.

This module is the single source of truth for:

1. **RiskLevel** — the four-band categorical risk label returned to the user.
2. **LLM gating constants** — deterministic score thresholds that decide
   whether the LLM call is skipped entirely (Smart Gating).
3. **Threshold mappings** — ordered lists that map a numeric score to a
   ``RiskLevel`` for both the deterministic-only path and the full
   (deterministic + LLM) path.

Smart Gating rationale
======================
The LLM call is the most expensive part of the pipeline (latency + cost).
We skip it in two cases:

* **Score < LLM_LOWER_THRESHOLD (10.0)**: The deterministic layer found
  almost nothing.  The email is almost certainly benign.  Calling the LLM
  would waste tokens and add latency for no benefit.

* **Score > LLM_UPPER_THRESHOLD (90.0)**: The deterministic layer found
  overwhelming technical evidence of malice (e.g. CRITICAL MIME mismatch +
  known-malicious URL + authentication failure).  The verdict is already
  definitive.  The LLM cannot make it *more* malicious, and we do not want
  to risk a hallucinated "benign" verdict overriding hard technical facts.

In both gated cases the response includes a ``semantic_warning`` that is
*informational* ("Skipped for efficiency") rather than alarming.

When the LLM is in the gray zone (10.0 ≤ score ≤ 90.0) but fails or times
out, the ``semantic_warning`` is a **high-visibility security alert** because
the user is in a genuinely ambiguous zone where semantic reasoning matters.

Design notes
============
* Zero framework imports — pure Python.
* ``RiskLevel`` is a ``str`` enum so it serialises cleanly to JSON.
* Threshold lists are ordered highest-first so the first match wins.
"""
from __future__ import annotations

from enum import Enum
from typing import Final

# ---------------------------------------------------------------------------
# RiskLevel enum
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """Categorical risk band for the final verdict.

    Bands correspond to the score ranges defined in plan.md:

    * BENIGN          — 0–19   (safe to proceed)
    * SUSPICIOUS      — 20–59  (verify if unexpected / via separate channel)
    * LIKELY_MALICIOUS — 60–79  (do not click or reply)
    * MALICIOUS       — 80–100 (report to security team)

    Note: ``LIKELY_MALICIOUS`` is the highest band available on the
    deterministic-only path (``DET_ONLY_THRESHOLDS``).  ``MALICIOUS``
    requires LLM confirmation (``FULL_THRESHOLDS``).
    """

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    MALICIOUS = "malicious"


# ---------------------------------------------------------------------------
# LLM gating constants
# ---------------------------------------------------------------------------

# Below this deterministic score → skip LLM (email is almost certainly benign).
LLM_LOWER_THRESHOLD: Final[float] = 10.0

# Above this deterministic score → skip LLM (technical signals are definitive).
LLM_UPPER_THRESHOLD: Final[float] = 90.0

# ---------------------------------------------------------------------------
# Semantic warning messages
# ---------------------------------------------------------------------------

# Used when LLM is skipped by the gating logic (informational, not alarming).
SEMANTIC_WARNING_GATED: Final[str] = (
    "ℹ Semantic analysis skipped for efficiency: The deterministic score "
    "was outside the range where AI reasoning adds value. "
    "The verdict is based on technical signals only."
)

# Used when LLM was attempted but failed (high-visibility security alert).
SEMANTIC_WARNING_FAILED: Final[str] = (
    "⚠ AI analysis failed — proceed with caution: The semantic reasoning "
    "layer (which detects social-engineering cues, urgency framing, and "
    "impersonation pretexts) encountered an error or timed out. "
    "This verdict is based on technical signals only. "
    "Verify via a separate channel before acting on this email."
)

# ---------------------------------------------------------------------------
# Threshold mappings
# ---------------------------------------------------------------------------
# Each list is ordered highest-first.  The first entry whose threshold is
# ≤ the score wins.  Use ``score_to_risk_level()`` to apply them.

# Deterministic-only path: capped at LIKELY_MALICIOUS (no LLM confirmation).
DET_ONLY_THRESHOLDS: Final[list[tuple[float, RiskLevel]]] = [
    (80.0, RiskLevel.LIKELY_MALICIOUS),
    (40.0, RiskLevel.SUSPICIOUS),
    (0.0, RiskLevel.BENIGN),
]

# Full path (deterministic + LLM fused score): includes MALICIOUS band.
FULL_THRESHOLDS: Final[list[tuple[float, RiskLevel]]] = [
    (80.0, RiskLevel.MALICIOUS),
    (60.0, RiskLevel.LIKELY_MALICIOUS),
    (20.0, RiskLevel.SUSPICIOUS),
    (0.0, RiskLevel.BENIGN),
]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def score_to_risk_level(
    score: float,
    thresholds: list[tuple[float, RiskLevel]],
) -> RiskLevel:
    """Map a numeric score to a :class:`RiskLevel` using the given thresholds.

    Args:
        score: A float in the range 0–100.
        thresholds: An ordered list of ``(min_score, RiskLevel)`` tuples,
            sorted highest-first.  The first entry whose ``min_score`` is
            ≤ ``score`` is returned.

    Returns:
        The matching :class:`RiskLevel`.  Falls back to ``BENIGN`` if no
        threshold matches (should not happen with a well-formed list).
    """
    for min_score, level in thresholds:
        if score >= min_score:
            return level
    return RiskLevel.BENIGN
