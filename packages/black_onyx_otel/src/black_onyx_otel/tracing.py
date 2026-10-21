"""Optional tracing bootstrap.

When OpenTelemetry packages are installed and OTEL_EXPORTER_OTLP_ENDPOINT is set,
exports via OTLP/HTTP. Otherwise configures a console/no-op provider safely.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("black_onyx_otel")

_INITIALIZED = False


def setup_tracing(service_name: str) -> Any | None:
    """Configure a TracerProvider for ``service_name``.

    Returns the tracer provider when configured, otherwise ``None``.
    Never raises for missing optional dependencies.
    """
    global _INITIALIZED
    if _INITIALIZED:
        return None

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    except ImportError:
        logger.debug("OpenTelemetry SDK not installed; tracing disabled for %s", service_name)
        return None

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.namespace": os.getenv("OTEL_SERVICE_NAMESPACE", "black-onyx-detection"),
        }
    )
    provider = TracerProvider(resource=resource)
    endpoint = (os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or "").strip()

    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            # Exporter reads OTEL_EXPORTER_OTLP_* env vars (base endpoint + /v1/traces).
            exporter: Any = OTLPSpanExporter()
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info("OTLP tracing enabled for %s -> %s", service_name, endpoint)
        except ImportError:
            logger.warning(
                "OTLP exporter not installed; falling back to console exporter for %s",
                service_name,
            )
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        except Exception:  # noqa: BLE001
            logger.exception("failed to configure OTLP exporter for %s", service_name)
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:
        # No endpoint: keep provider registered but avoid noisy console export by default.
        if os.getenv("OTEL_TRACES_CONSOLE", "").lower() in {"1", "true", "yes"}:
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        logger.debug("OTEL_EXPORTER_OTLP_ENDPOINT unset; tracing no-op/console for %s", service_name)

    trace.set_tracer_provider(provider)
    _INITIALIZED = True
    return provider
