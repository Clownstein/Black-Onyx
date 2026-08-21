from contextlib import asynccontextmanager

from fastapi import FastAPI

from ids_processor.config import settings
from ids_processor.kafka_io import IdsConsumer

try:
    from black_onyx_otel import install_prometheus_endpoint, setup_tracing

    setup_tracing("ids-processor")
except ImportError:
    install_prometheus_endpoint = None  # type: ignore[assignment]

consumer = IdsConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    consumer.start()
    yield
    consumer.stop()


app = FastAPI(title="IDS Processor", version="0.1.0", lifespan=lifespan)
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
        "findings_published": consumer.pipeline.findings_published,
        "errors": consumer.pipeline.errors,
        "kafka_enabled": settings.enable_kafka,
        "publish_findings": settings.publish_findings,
    }
    if consumer.last_error:
        payload["error"] = consumer.last_error
    return payload


@app.post("/v1/process")
def process_batch(body: dict) -> dict[str, object]:
    events = body.get("events") or []
    findings = consumer.process_batch(events)
    return {
        "findings_count": len(findings),
        "findings": findings,
    }


def run() -> None:
    import uvicorn

    uvicorn.run("ids_processor.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
