"""Optional Prometheus metrics helpers.

Base install has no metrics dependencies. Install the ``metrics`` extra
(``prometheus-client``) to expose a real ``/metrics`` endpoint on FastAPI apps.

Without ``prometheus-client``, counters are in-process no-ops and
``install_prometheus_endpoint`` mounts a minimal text exposition using those
counters so scrapes still succeed.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger("black_onyx_otel")

_INITIALIZED = False
_LOCK = threading.Lock()
_COUNTERS: dict[str, float] = {}
_USE_PROM_CLIENT = False
_PROM_COUNTERS: dict[str, Any] = {}


def setup_metrics(service_name: str) -> bool:
    """Initialize metrics for ``service_name``.

    Returns ``True`` when ``prometheus_client`` is available, otherwise ``False``.
    Never raises for missing optional dependencies. Idempotent.
    """
    global _INITIALIZED, _USE_PROM_CLIENT
    if _INITIALIZED:
        return _USE_PROM_CLIENT

    with _LOCK:
        if _INITIALIZED:
            return _USE_PROM_CLIENT
        try:
            import prometheus_client  # noqa: F401

            _USE_PROM_CLIENT = True
            logger.info("prometheus-client metrics enabled for %s", service_name)
        except ImportError:
            _USE_PROM_CLIENT = False
            logger.debug(
                "prometheus-client not installed; using in-process counters for %s",
                service_name,
            )
        _INITIALIZED = True
        return _USE_PROM_CLIENT


def counter(name: str, documentation: str = "", labelnames: tuple[str, ...] = ()) -> Any:
    """Return a counter handle.

    With ``prometheus-client``: a labeled ``Counter`` (call ``.labels(...).inc()``).
    Without it: a simple callable ``inc(amount=1, **labels)`` backed by
    ``_COUNTERS``.
    """
    setup_metrics("black-onyx-detection")
    if _USE_PROM_CLIENT:
        if name not in _PROM_COUNTERS:
            from prometheus_client import Counter

            _PROM_COUNTERS[name] = Counter(name, documentation or name, labelnames=list(labelnames))
        return _PROM_COUNTERS[name]

    def _inc(amount: float = 1.0, **labels: str) -> None:
        key = name
        if labels:
            parts = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
            key = f"{name}{{{parts}}}"
        with _LOCK:
            _COUNTERS[key] = _COUNTERS.get(key, 0.0) + float(amount)

    return _inc


def inc_counter(name: str, amount: float = 1.0, **labels: str) -> None:
    """Increment a named counter (creates it if needed)."""
    handle = counter(name, documentation=name, labelnames=tuple(sorted(labels.keys())))
    if _USE_PROM_CLIENT:
        if labels:
            handle.labels(**labels).inc(amount)
        else:
            handle.inc(amount)
    else:
        handle(amount, **labels)


def render_metrics_text() -> str:
    """Render Prometheus text exposition for in-process counters."""
    setup_metrics("black-onyx-detection")
    if _USE_PROM_CLIENT:
        from prometheus_client import generate_latest

        return generate_latest().decode("utf-8")  # type: ignore[no-any-return]

    lines: list[str] = []
    with _LOCK:
        for key, value in sorted(_COUNTERS.items()):
            lines.append(f"{key} {value}")
    if not lines:
        lines.append("# black_onyx_otel in-process metrics (no samples yet)")
    return "\n".join(lines) + "\n"


def install_prometheus_endpoint(app: Any, path: str = "/metrics") -> bool:
    """Mount ``GET /metrics`` on a FastAPI (or Starlette) ``app``.

    Prefers ``prometheus_client`` exposition when installed; otherwise serves
    ``render_metrics_text()``. Returns whether prometheus-client is active.
    Never raises for missing optional dependencies.
    """
    active = setup_metrics("black-onyx-detection")

    try:
        from fastapi import Response
    except ImportError:
        logger.debug("FastAPI not available; skipping /metrics mount")
        return active

    if active:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        @app.get(path)
        def _metrics() -> Response:
            return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    else:

        @app.get(path)
        def _metrics() -> Response:
            return Response(content=render_metrics_text(), media_type="text/plain; version=0.0.4")

    return active
