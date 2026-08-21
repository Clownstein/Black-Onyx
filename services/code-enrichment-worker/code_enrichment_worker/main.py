from contextlib import asynccontextmanager

from fastapi import FastAPI

from code_enrichment_worker.config import settings
from code_enrichment_worker.enrich import enrich_code
from code_enrichment_worker.kafka_io import EnrichmentConsumer

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("code-enrichment-worker")
except ImportError:
    pass

consumer = EnrichmentConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    consumer.start()
    yield
    consumer.stop()


app = FastAPI(
    title="Code Enrichment Worker",
    version="0.1.0",
    lifespan=lifespan,
    description=(
        "Async Antares CLI enrichment for high-risk code findings. "
        "Results are advisory leads requiring human review; no autonomous remediation."
    ),
)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    kafka_ok = consumer.ready or not settings.enable_kafka
    payload: dict[str, object] = {
        "status": "ready" if kafka_ok else "not_ready",
        "processed": consumer.processed,
        "errors": consumer.errors,
        "kafka_enabled": settings.enable_kafka,
        "poll_findings": settings.poll_findings,
        "antares_endpoint_set": bool((settings.antares_endpoint or "").strip()),
        "human_review_required": True,
        "autonomous_remediation": False,
    }
    if consumer.last_error:
        payload["error"] = consumer.last_error
    return payload


@app.post("/api/v1/code/enrich")
def enrich_endpoint(body: dict) -> dict[str, object]:
    """Run Antares plan (+ optional tool query/sweep) and post evidence to incident-api."""
    result = enrich_code(body if isinstance(body, dict) else {})
    consumer.processed += 1
    return result


def run() -> None:
    import uvicorn

    uvicorn.run("code_enrichment_worker.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
