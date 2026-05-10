"""Domain models for the malicious email scorer.

All models are immutable dataclasses (frozen=True, kw_only=True) — pure Python,
zero framework imports — in keeping with the hexagonal / ports-and-adapters
architecture where the domain layer has no external dependencies.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from app.domain.enums import Category, RiskLevel, Severity


@dataclass(frozen=True, kw_only=True)
class EmailContext:
    """Represents the full context of an email to be analysed.

    Attributes:
        sender: The RFC 5321 envelope sender address (MAIL FROM).
        recipient: The primary recipient address.
        subject: The decoded email subject line.
        body: The plain-text (or HTML-stripped) body of the email.
        headers: A mapping of header name → value for all relevant headers
            (e.g. ``Received``, ``Authentication-Results``, ``DKIM-Signature``).
        attachment_metadata: A list of metadata dicts for each attachment.
            Each dict should contain at minimum ``filename``, ``mime_type``,
            and ``size_bytes``.  Attachment *bytes* are never stored here.
    """

    sender: str
    recipient: str
    subject: str
    body: str
    headers: dict[str, str] = field(default_factory=dict)
    attachment_metadata: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, kw_only=True)
class Finding:
    """A single security finding produced by a deterministic analyser.

    Attributes:
        id: A UUID that uniquely identifies this finding instance.
        type: The :class:`~app.domain.enums.Category` of the finding.
        severity: The :class:`~app.domain.enums.Severity` of the finding.
        description: A human-readable description of what was detected.
        evidence: A free-form dict of supporting evidence (e.g. extracted
            URLs, header values, domain names) that backs the finding.
    """

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    type: Category
    severity: Severity
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class AnalysisVerdict:
    """The final verdict produced by the LLM after reviewing all findings.

    Attributes:
        score: An integer in the range 0–100 representing overall maliciousness.
            0 = completely benign, 100 = highly malicious.
        risk_level: A coarse :class:`~app.domain.enums.RiskLevel` bucket derived
            from the score.
        findings: The list of :class:`Finding` objects that informed the verdict.
        rational: A concise, human-readable explanation of the verdict produced
            by the LLM (semantic reasoning only — no hallucinated facts).
    """

    score: int  # 0–100
    risk_level: RiskLevel
    findings: list[Finding]
    rational: str
