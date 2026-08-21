from contextlib import asynccontextmanager

from fastapi import FastAPI

from firewall_processor.config import settings
from firewall_processor.kafka_io import FirewallConsumer

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("firewall-processor")
except ImportError:
    pass

consumer = FirewallConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    consumer.start()
    yield
    consumer.stop()


app = FastAPI(title="Firewall Processor", version="0.1.0", lifespan=lifespan)


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
    }
    if consumer.last_error:
        payload["error"] = consumer.last_error
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

    uvicorn.run("firewall_processor.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
