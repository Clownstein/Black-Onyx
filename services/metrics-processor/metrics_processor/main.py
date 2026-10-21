from contextlib import asynccontextmanager
import secrets
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from metrics_processor.config import settings
from metrics_processor.kafka_io import MetricsConsumer
from metrics_processor.request_limits import RequestBodyLimitMiddleware

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("metrics-processor")
except ImportError:
    pass

consumer = MetricsConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    consumer.start()
    yield
    consumer.stop()


app = FastAPI(title="Metrics Processor", version="0.1.0", lifespan=lifespan)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=16 * 1024 * 1024)


class ProcessBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=500)


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not settings.api_key:
        raise HTTPException(status_code=503, detail="processor API key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    ready_now = bool(settings.api_key) and (consumer.ready or not settings.enable_kafka)
    payload: dict[str, object] = {
        "status": "ready" if ready_now else "not_ready",
        "api_key_configured": bool(settings.api_key),
        "processed": consumer.pipeline.processed,
        "published": consumer.pipeline.published,
        "errors": consumer.pipeline.errors,
        "profile": settings.profile,
        "kafka_enabled": settings.enable_kafka,
    }
    if consumer.last_error:
        payload["error"] = consumer.last_error
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


@app.post("/v1/process")
def process_batch(body: ProcessBatch, _: None = Depends(require_api_key)) -> dict[str, object]:
    features = consumer.process_batch(body.events)
    return {"count": len(features), "features": features}


def run() -> None:
    import uvicorn

    uvicorn.run("metrics_processor.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
