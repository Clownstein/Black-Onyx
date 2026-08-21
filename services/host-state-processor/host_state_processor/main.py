from contextlib import asynccontextmanager

from fastapi import FastAPI

from host_state_processor.config import settings
from host_state_processor.kafka_io import HostStateConsumer

consumer = HostStateConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    consumer.start()
    yield
    consumer.stop()


app = FastAPI(title="Host State Processor", version="0.1.0", lifespan=lifespan)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "ready" if consumer.ready or not settings.enable_kafka else "not_ready",
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
    return payload


@app.post("/v1/process")
def process_batch(body: dict) -> dict[str, object]:
    events = body.get("events") or []
    features, findings = consumer.process_batch(events)
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
