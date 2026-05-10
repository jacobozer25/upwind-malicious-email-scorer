"""
backend/app/analyzers/orchestrator.py
---------------------------------------
Analyzer orchestrator for the malicious email scorer.

The orchestrator is the single coordination point for the deterministic
analysis layer.  It accepts a list of :class:`~app.domain.ports.AnalyzerPort`
instances at construction time (dependency injection) and runs them all in
parallel via :func:`asyncio.gather`.

Concurrency model
=================
* All analyzers are launched simultaneously with ``asyncio.gather(
  return_exceptions=True)``.
* The entire gather is wrapped in ``asyncio.wait_for`` with a global timeout
  of 1.5 seconds.  If the timeout fires, whatever findings have already been
  collected are returned and a warning is logged.
* If an individual analyzer raises an exception (e.g. a bug in the analyzer
  code), the exception is caught, logged, and that analyzer's findings are
  simply omitted — the orchestrator never crashes.

Design notes
============
* The orchestrator has zero knowledge of *which* analyzers are injected.
  The caller (``AnalyzeEmailUseCase``) is responsible for wiring the concrete
  analyzer instances.
* Results are flattened from ``list[list[Finding]]`` to ``list[Finding]``
  before being returned.
* The global timeout is intentionally conservative (1.5 s) to keep the
  deterministic layer well within the overall request budget.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Final

from app.domain.models import EmailContext, Finding
from app.domain.ports import AnalyzerPort

log = logging.getLogger(__name__)

# Global timeout for the entire deterministic layer (seconds).
_GLOBAL_TIMEOUT_SECONDS: Final[float] = 1.5


class AnalyzerOrchestrator:
    """Runs all injected deterministic analyzers in parallel.

    Args:
        analyzers: A list of :class:`~app.domain.ports.AnalyzerPort` instances
            to run.  The list may be empty (returns no findings).

    Example::

        orchestrator = AnalyzerOrchestrator(
            analyzers=[
                HeadersAnalyzer(),
                DomainsAnalyzer(),
                AttachmentsAnalyzer(),
                TemporalAnalyzer(),
                ContentAnalyzer(),
                ReputationAnalyzer(),
            ]
        )
        findings = await orchestrator.analyze_all(context)
    """

    def __init__(self, analyzers: list[AnalyzerPort]) -> None:
        self._analyzers = analyzers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_all(self, context: EmailContext) -> list[Finding]:
        """Run all analyzers concurrently and return the merged findings.

        The method:

        1. Launches every analyzer's ``analyze()`` coroutine simultaneously.
        2. Waits for all of them to complete, up to ``_GLOBAL_TIMEOUT_SECONDS``.
        3. Collects results, skipping any analyzer that raised an exception.
        4. Flattens the per-analyzer finding lists into a single list.

        Args:
            context: The :class:`~app.domain.models.EmailContext` to analyze.

        Returns:
            A flat list of :class:`~app.domain.models.Finding` objects from
            all analyzers that completed successfully within the timeout.
        """
        if not self._analyzers:
            return []

        # Build one coroutine per analyzer.
        coros = [analyzer.analyze(context) for analyzer in self._analyzers]

        try:
            raw_results: list[list[Finding] | BaseException] = await asyncio.wait_for(
                asyncio.gather(*coros, return_exceptions=True),
                timeout=_GLOBAL_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            log.warning(
                "orchestrator.global_timeout",
                extra={
                    "timeout_seconds": _GLOBAL_TIMEOUT_SECONDS,
                    "analyzer_count": len(self._analyzers),
                    "detail": (
                        "The deterministic layer exceeded the global timeout. "
                        "Returning an empty findings list; the LLM layer will "
                        "proceed with reduced context."
                    ),
                },
            )
            return []

        # Process results: flatten successes, log failures.
        findings: list[Finding] = []
        for analyzer, result in zip(self._analyzers, raw_results):
            analyzer_name = type(analyzer).__name__
            if isinstance(result, BaseException):
                log.error(
                    "orchestrator.analyzer_failed",
                    extra={
                        "analyzer": analyzer_name,
                        "error": str(result)[:300],
                        "error_type": type(result).__name__,
                    },
                    exc_info=result,
                )
                # Skip this analyzer's findings — do not crash.
                continue

            if not isinstance(result, list):
                log.warning(
                    "orchestrator.unexpected_result_type",
                    extra={
                        "analyzer": analyzer_name,
                        "result_type": type(result).__name__,
                    },
                )
                continue

            log.debug(
                "orchestrator.analyzer_completed",
                extra={
                    "analyzer": analyzer_name,
                    "finding_count": len(result),
                },
            )
            findings.extend(result)

        return findings
