from contextlib import asynccontextmanager
import secrets
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

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


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.api_key.strip()
    if not expected:
        raise HTTPException(status_code=503, detail="embedding API key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


class EmbedTextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=32_768)


class EmbedFindingRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    tenant_id: str = Field(min_length=1, max_length=128)
    finding_id: str = Field(min_length=1, max_length=256)
    finding_type: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def bounded_payload(self) -> "EmbedFindingRequest":
        window = self.model_extra.get("window") if self.model_extra else None
        occurred_at = self.model_extra.get("occurred_at") if self.model_extra else None
        if not occurred_at and not (isinstance(window, dict) and window.get("end")):
            raise ValueError("occurred_at or window.end is required")
        if len(self.model_dump_json().encode("utf-8")) > 1_048_576:
            raise ValueError("finding payload exceeds 1 MiB")
        return self


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    kafka_ok = consumer.ready or not settings.enable_kafka
    embedding_ok = not settings.vector_search_enabled or embedder.available()
    qdrant_ok = not settings.vector_search_enabled or ensure_collections()
    key_configured = bool(settings.api_key.strip())
    ready_now = kafka_ok and embedding_ok and qdrant_ok and key_configured
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready_now else "not_ready",
        "processed": consumer.processed,
        "upserted": consumer.upserted,
        "errors": consumer.errors,
        "kafka_enabled": settings.enable_kafka,
        "vector_search_enabled": settings.vector_search_enabled,
        "embedding_ready": embedding_ok,
        "qdrant_ready": qdrant_ok,
        "embedding_last_error": embedder.last_error,
        "last_error": consumer.last_error,
        "api_key_configured": key_configured,
    }


@app.post("/api/v1/embed/finding")
def embed_finding(
    body: EmbedFindingRequest, _: None = Depends(require_api_key)
) -> dict[str, object]:
    """Embed and upsert a single finding (used by tests and manual backfill)."""

    result = process_finding(body.model_dump())
    consumer.processed += 1
    if result.get("status") == "upserted":
        consumer.upserted += 1
    return result


@app.post("/api/v1/embed/text")
def embed_text(body: EmbedTextRequest, _: None = Depends(require_api_key)) -> dict[str, object]:
    """Return the embedding vector for arbitrary text (for hunt-by-example)."""

    text = body.text
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
