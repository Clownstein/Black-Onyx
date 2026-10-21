from contextlib import asynccontextmanager
import secrets
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from host_state_processor.config import settings
from host_state_processor.kafka_io import HostStateConsumer
from host_state_processor.request_limits import RequestBodyLimitMiddleware

consumer = HostStateConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    consumer.start()
    yield
    consumer.stop()


app = FastAPI(title="Host State Processor", version="0.1.0", lifespan=lifespan)
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
        "findings_published": consumer.pipeline.findings_published,
        "errors": consumer.pipeline.errors,
        "kafka_enabled": settings.enable_kafka,
        "publish_findings": settings.publish_findings,
        "heartbeat_enabled": settings.enable_heartbeat,
        "heartbeat_sweeps": consumer.heartbeat.sweeps,
        "telemetry_gaps_published": consumer.heartbeat.gaps_published,
        "heartbeat_errors": consumer.heartbeat.errors,
    }
    if consumer.last_error:
        payload["error"] = consumer.last_error
    if consumer.heartbeat.last_error:
        payload["heartbeat_error"] = consumer.heartbeat.last_error
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


@app.post("/v1/process")
def process_batch(body: ProcessBatch, _: None = Depends(require_api_key)) -> dict[str, object]:
    features, findings = consumer.process_batch(body.events)
    return {
        "count": len(features),
        "features": features,
        "findings_count": len(findings),
        "findings": findings,
    }


def run() -> None:
    import uvicorn

    uvicorn.run("host_state_processor.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
