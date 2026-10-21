"""Minimal OpenTelemetry helpers for platform services."""

from black_onyx_otel.metrics import (
    counter,
    inc_counter,
    install_prometheus_endpoint,
    setup_metrics,
)
from black_onyx_otel.tracing import setup_tracing

__all__ = [
    "setup_tracing",
    "setup_metrics",
    "install_prometheus_endpoint",
    "counter",
    "inc_counter",
]
__version__ = "0.1.0"
