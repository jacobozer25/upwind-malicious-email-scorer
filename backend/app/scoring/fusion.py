"""
backend/app/scoring/fusion.py
-------------------------------
Score fusion functions for the malicious email scorer.

This module provides two pure functions:

1. :func:`calculate_deterministic_score` — converts a list of
   :class:`~app.domain.models.Finding` objects into a single 0–100 float
   by summing per-severity weights and capping at 100.

2. :func:`fuse_scores` — combines the deterministic score and the LLM
   semantic score into a single fused score using a weighted formula:
   ``(det × 0.45) + (llm × 0.55)``.

Design notes
============
* Pure functions — no I/O, no side effects, trivially testable.
* Zero framework imports.
* Severity weights are intentionally asymmetric: CRITICAL findings carry
  disproportionate weight (40 pts) because they represent hard technical
  facts (e.g. known-malicious URL, executable MIME type) that are never
  hallucinated.
* The LLM weight (0.55) is slightly higher than the deterministic weight
  (0.45) because the LLM performs semantic reasoning that the deterministic
  layer cannot (social engineering, urgency framing, impersonation pretext).
  However, the LLM score is only used when the deterministic score is in the
  gray zone (10–90); outside that range the LLM is gated and only the
  deterministic score is used.
"""
from __future__ import annotations

from typing import Final

from app.domain.enums import Severity
from app.domain.models import Finding

# ---------------------------------------------------------------------------
# Severity → score contribution weights
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: Final[dict[Severity, float]] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 12.0,
    Severity.LOW: 4.0,
}

# ---------------------------------------------------------------------------
# Fusion weights
# ---------------------------------------------------------------------------

_DETERMINISTIC_WEIGHT: Final[float] = 0.45
_LLM_WEIGHT: Final[float] = 0.55

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def calculate_deterministic_score(findings: list[Finding]) -> float:
    """Compute a 0–100 deterministic score from a list of findings.

    Each finding contributes a fixed number of points based on its severity:

    * CRITICAL → 40 pts
    * HIGH     → 25 pts
    * MEDIUM   → 12 pts
    * LOW      →  4 pts

    The raw sum is capped at 100.0.

    Args:
        findings: The list of :class:`~app.domain.models.Finding` objects
            produced by the deterministic analyzers.

    Returns:
        A float in the range [0.0, 100.0].
    """
    raw = sum(_SEVERITY_WEIGHTS.get(f.severity, 0.0) for f in findings)
    return min(raw, 100.0)


def fuse_scores(det_score: float, llm_score: float) -> float:
    """Fuse the deterministic and LLM scores into a single final score.

    Formula::

        fused = (det_score × 0.45) + (llm_score × 0.55)

    The result is capped at 100.0.

    Args:
        det_score: The deterministic score in [0.0, 100.0].
        llm_score: The LLM semantic score in [0.0, 100.0].

    Returns:
        A float in the range [0.0, 100.0].
    """
    fused = (det_score * _DETERMINISTIC_WEIGHT) + (llm_score * _LLM_WEIGHT)
    return min(fused, 100.0)
