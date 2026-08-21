from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
import secrets
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from inference_worker.config import settings
from inference_worker.worker import InferenceWorker

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("inference-worker")
except ImportError:
    pass

logger = logging.getLogger("inference-worker")
logging.basicConfig(level=logging.INFO)

worker = InferenceWorker()
_consumer_task: asyncio.Task[None] | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _consumer_task
    try:
        await worker.start()
        _consumer_task = asyncio.create_task(worker.run_forever())
    except Exception:  # noqa: BLE001 - API should still serve health/score-once
        logger.exception("kafka consumer failed to start; HTTP endpoints remain available")
        worker.ready = False
    yield
    if _consumer_task is not None:
        _consumer_task.cancel()
        try:
            await _consumer_task
        except asyncio.CancelledError:
            pass
        _consumer_task = None
    await worker.stop()


app = FastAPI(title="Inference Worker", version="0.1.0", lifespan=lifespan)


class ScoreOnceRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    model_name: str
    feature: dict[str, Any] = Field(default_factory=dict)


def _require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.api_key
    if not expected:
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    return {
        "status": "ready" if worker.ready else "degraded",
        "use_model_gateway": settings.use_model_gateway,
        "model_gateway_url": settings.model_gateway_url,
        "topics": settings.consume_topics(),
        "processed": worker.processed,
        "published": worker.published,
        "dlq": worker.dlq_count,
        "errors": worker.errors,
        "last_error": worker.last_error,
        "api_key_required": bool(settings.api_key),
    }


@app.post("/v1/score-once")
async def score_once(
    body: ScoreOnceRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> dict[str, Any]:
    """Synchronous score endpoint for tests and manual probing."""
    _require_api_key(x_api_key)
    try:
        finding = await worker.score_feature(body.model_name, body.feature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"predict failed: {exc}") from exc
    return {"status": "ok", "finding": finding}


def run() -> None:
    import uvicorn

    uvicorn.run("inference_worker.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
