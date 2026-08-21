from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from embedding_worker.config import settings
from embedding_worker.embed import EmbeddingUnavailableError, embedder
from embedding_worker.kafka_io import EmbeddingConsumer
from embedding_worker.worker import ensure_collections, process_finding

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("embedding-worker")
except ImportError:
    pass

consumer = EmbeddingConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    consumer.start()
    if settings.vector_search_enabled:
        # Best-effort; soft-fails when Qdrant is down / disabled.
        ensure_collections()
    yield
    consumer.stop()


app = FastAPI(
    title="Embedding Worker",
    version="0.1.0",
    lifespan=lifespan,
    description=(
        "Consumes findings, embeds their summary text with SecureBERT 2.0, and "
        "upserts them into Qdrant. Optional dependencies report explicit "
        "disabled/degraded capability states."
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
    embedding_ok = not settings.vector_search_enabled or embedder.available()
    qdrant_ok = not settings.vector_search_enabled or ensure_collections()
    return {
        "status": "ready" if kafka_ok and embedding_ok and qdrant_ok else "not_ready",
        "processed": consumer.processed,
        "upserted": consumer.upserted,
        "errors": consumer.errors,
        "kafka_enabled": settings.enable_kafka,
        "vector_search_enabled": settings.vector_search_enabled,
        "embedding_ready": embedding_ok,
        "qdrant_ready": qdrant_ok,
        "embedding_last_error": embedder.last_error,
        "last_error": consumer.last_error,
    }


@app.post("/api/v1/embed/finding")
def embed_finding(body: dict) -> dict[str, object]:
    """Embed and upsert a single finding (used by tests and manual backfill)."""

    result = process_finding(body if isinstance(body, dict) else {})
    consumer.processed += 1
    if result.get("status") == "upserted":
        consumer.upserted += 1
    return result


@app.post("/api/v1/embed/text")
def embed_text(body: dict) -> dict[str, object]:
    """Return the embedding vector for arbitrary text (for hunt-by-example)."""

    text = str((body or {}).get("text") or "")
    try:
        vector = embedder.embed(text)
    except EmbeddingUnavailableError as exc:
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "capability": "text_embedding",
                "reason": str(exc),
                "retry_after_seconds": 30,
            },
        )
    return {
        "status": "ready",
        "capability": "text_embedding",
        "dim": len(vector),
        "vector": vector,
    }


def run() -> None:
    import uvicorn

    uvicorn.run("embedding_worker.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
