"""Port (abstract base class) definitions for the malicious email scorer.

Ports define the *interfaces* that the domain layer expects from the outside
world.  Concrete adapters (e.g. the OpenAI provider, individual analysers)
implement these ABCs.  The domain layer itself never imports any adapter.

This keeps the domain layer framework-free and makes every adapter trivially
swappable and independently testable.
"""

from __future__ import annotations

import abc

from app.domain.models import AnalysisVerdict, EmailContext, Finding


class AnalyzerPort(abc.ABC):
    """Interface for a single deterministic email analyser.

    Each concrete analyser (headers, domains, links, attachments, temporal,
    content, reputation) implements this port.  Analysers are run in parallel
    by the orchestrator via ``asyncio.gather``.
    """

    @abc.abstractmethod
    async def analyze(self, context: EmailContext) -> list[Finding]:
        """Analyse the given email context and return zero or more findings.

        Args:
            context: The full :class:`~app.domain.models.EmailContext` for the
                email being evaluated.

        Returns:
            A (possibly empty) list of :class:`~app.domain.models.Finding`
            objects representing security signals detected by this analyser.
        """


class LLMPort(abc.ABC):
    """Interface for the LLM provider used for semantic reasoning.

    The LLM is given the email context *and* the deterministic findings so that
    it can perform semantic reasoning (social engineering, urgency framing,
    impersonation pretext) without needing to produce any facts itself.
    """

    @abc.abstractmethod
    async def analyze_semantic(
        self,
        context: EmailContext,
        findings: list[Finding],
    ) -> AnalysisVerdict:
        """Perform semantic analysis and return a final verdict.

        Args:
            context: The full :class:`~app.domain.models.EmailContext` for the
                email being evaluated.
            findings: The list of :class:`~app.domain.models.Finding` objects
                produced by the deterministic layer.  The LLM uses these as
                grounding evidence and must not contradict them.

        Returns:
            An :class:`~app.domain.models.AnalysisVerdict` containing the fused
            score, risk level, findings, and a human-readable rationale.
        """
