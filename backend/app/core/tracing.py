"""
backend/app/core/tracing.py
-----------------------------
OpenTelemetry tracing hooks (optional — wired but not required).

If the ``opentelemetry-sdk`` package is not installed, this module is a
no-op. The application starts normally without tracing.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def configure_tracing(settings: object | None = None) -> None:
    """Configure OpenTelemetry tracing if the SDK is available.

    This is a best-effort setup — if the SDK is not installed or the
    OTLP endpoint is not configured, tracing is silently disabled.
    """
    try:
        from opentelemetry import trace  # type: ignore[import]
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import]
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore[import]

        otlp_endpoint = getattr(settings, "otlp_endpoint", None)
        if not otlp_endpoint:
            log.debug("tracing.disabled", extra={"reason": "OTLP_ENDPOINT not set"})
            return

        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore[import]
            OTLPSpanExporter,
        )

        provider = TracerProvider()
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        log.info("tracing.configured", extra={"endpoint": otlp_endpoint})

    except ImportError:
        log.debug(
            "tracing.disabled",
            extra={"reason": "opentelemetry-sdk not installed"},
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "tracing.setup_failed",
            extra={"error": str(exc)},
        )
