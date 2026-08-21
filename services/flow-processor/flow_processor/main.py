from contextlib import asynccontextmanager

from fastapi import FastAPI

from flow_processor.config import settings
from flow_processor.kafka_io import FlowConsumer

try:
    from black_onyx_otel import install_prometheus_endpoint, setup_tracing

    setup_tracing("flow-processor")
except ImportError:
    install_prometheus_endpoint = None  # type: ignore[assignment]

consumer = FlowConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    consumer.start()
    yield
    consumer.stop()


app = FastAPI(title="Flow Processor", version="0.1.0", lifespan=lifespan)
if install_prometheus_endpoint is not None:
    try:
        install_prometheus_endpoint(app)
    except Exception:
        pass


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "ready" if consumer.ready or not settings.enable_kafka else "not_ready",
        "processed": consumer.pipeline.processed,
        "published": consumer.pipeline.published,
        "errors": consumer.pipeline.errors,
        "kafka_enabled": settings.enable_kafka,
    }
    if consumer.last_error:
        payload["error"] = consumer.last_error
    return payload


@app.post("/v1/process")
def process_batch(body: dict) -> dict[str, object]:
    events = body.get("events") or []
    features = consumer.process_batch(events)
    return {"count": len(features), "features": features}


def run() -> None:
    import uvicorn

    uvicorn.run("flow_processor.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
