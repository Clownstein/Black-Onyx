from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
import secrets
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Response, status
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


async def _consumer_supervisor() -> None:
    delay = 1.0
    while True:
        try:
            await worker.start()
            await worker.run_forever()
            raise RuntimeError("Kafka consumer stopped unexpectedly")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - recover the processing task
            worker.ready = False
            worker.last_error = type(exc).__name__
            logger.exception("inference consumer failed; restarting in %.1fs", delay)
            try:
                await worker.stop()
            except Exception:  # noqa: BLE001
                logger.exception("inference consumer cleanup failed")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _consumer_task
    _consumer_task = asyncio.create_task(_consumer_supervisor())
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

    model_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    feature: dict[str, Any] = Field(default_factory=dict)


def _require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.api_key
    if not expected:
        raise HTTPException(status_code=503, detail="inference API key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    key_configured = bool(settings.api_key)
    ready_now = worker.ready and key_configured
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready_now else "not_ready",
        "use_model_gateway": settings.use_model_gateway,
        "model_gateway_url": settings.model_gateway_url,
        "topics": settings.consume_topics(),
        "processed": worker.processed,
        "published": worker.published,
        "dlq": worker.dlq_count,
        "errors": worker.errors,
        "last_error": worker.last_error,
        "api_key_configured": key_configured,
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
