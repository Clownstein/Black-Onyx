from __future__ import annotations

import asyncio
import contextlib
import secrets
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Response, status

from profile_evaluator.client import IncidentApiClient
from profile_evaluator.config import settings
from profile_evaluator.evaluator import ProfileEvaluator
from profile_evaluator.probe import probe_targets

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("profile-evaluator")
except ImportError:
    pass


def _build_evaluator() -> ProfileEvaluator:
    return ProfileEvaluator(settings, IncidentApiClient(settings))


async def _run_loop(app: FastAPI) -> None:
    evaluator: ProfileEvaluator = app.state.evaluator
    while True:
        try:
            result = await asyncio.to_thread(evaluator.evaluate_once)
            app.state.last_result = result
        except Exception as exc:  # noqa: BLE001 loop must survive transient errors
            app.state.last_error = str(exc)
        await asyncio.sleep(max(settings.interval_sec, 1.0))


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.evaluator = _build_evaluator()
    app.state.last_result = None
    app.state.last_error = None
    app.state.loop_task = None
    if settings.enable_loop:
        app.state.loop_task = asyncio.create_task(_run_loop(app))
    try:
        yield
    finally:
        task = app.state.loop_task
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


app = FastAPI(title="Profile Evaluator", version="0.1.0", lifespan=lifespan)


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.api_key.strip()
    if not expected:
        raise HTTPException(status_code=503, detail="profile evaluator API key is not configured")
    if not settings.tenant_id.strip() or not settings.incident_api_service_key.strip():
        raise HTTPException(status_code=503, detail="profile evaluator upstream identity is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, Any]:
    configured = bool(
        settings.api_key.strip()
        and settings.tenant_id.strip()
        and settings.incident_api_service_key.strip()
    )
    if not configured:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if configured else "not_ready",
        "incident_api_url": settings.incident_api_url,
        "loop_enabled": settings.enable_loop,
        "interval_sec": settings.interval_sec,
        "vector_novelty_enabled": settings.vector_novelty_enabled,
        "probe_targets": len(settings.probe_url_list()),
        "api_key_configured": bool(settings.api_key),
        "tenant_configured": bool(settings.tenant_id),
        "incident_api_service_key_configured": bool(settings.incident_api_service_key),
    }


@app.post("/api/v1/profile-evaluator/evaluate")
def evaluate(_: None = Depends(require_api_key)) -> dict[str, Any]:
    evaluator: ProfileEvaluator = app.state.evaluator
    result = evaluator.evaluate_once()
    app.state.last_result = result
    return result


@app.get("/api/v1/profile-evaluator/probe")
def probe(_: None = Depends(require_api_key)) -> dict[str, Any]:
    urls = settings.probe_url_list()
    if not urls:
        return {"targets": [], "count": 0}
    with httpx.Client(
        timeout=settings.probe_timeout_sec, trust_env=False, follow_redirects=False
    ) as client:
        targets = probe_targets(urls, client=client, timeout=settings.probe_timeout_sec)
    return {"targets": targets, "count": len(targets)}


def run() -> None:
    import uvicorn

    uvicorn.run("profile_evaluator.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
