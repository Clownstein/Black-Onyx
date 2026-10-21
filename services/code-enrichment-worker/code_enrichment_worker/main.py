from contextlib import asynccontextmanager
import secrets
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from code_enrichment_worker.config import settings
from code_enrichment_worker.enrich import enrich_code
from code_enrichment_worker.kafka_io import EnrichmentConsumer
from code_enrichment_worker.request_limits import RequestBodyLimitMiddleware

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
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=16 * 1024 * 1024)


class EnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    tenant_id: str = Field(min_length=1, max_length=128)
    asset_id: str | None = Field(default=None, min_length=1, max_length=256)
    finding: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_request(self) -> "EnrichmentRequest":
        finding_asset = self.finding.get("asset_id") if isinstance(self.finding, dict) else None
        if not self.asset_id and not finding_asset:
            raise ValueError("asset_id is required")
        if len(self.model_dump_json().encode("utf-8")) > 1_048_576:
            raise ValueError("enrichment request exceeds 1 MiB")
        return self


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.api_key.strip()
    if not expected:
        raise HTTPException(status_code=503, detail="code enrichment API key is not configured")
    if not settings.incident_api_service_key.strip():
        raise HTTPException(status_code=503, detail="incident-api service key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    kafka_ok = consumer.ready or not settings.enable_kafka
    api_key_configured = bool(settings.api_key.strip())
    incident_key_configured = bool(settings.incident_api_service_key.strip())
    ready_now = kafka_ok and api_key_configured and incident_key_configured
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    payload: dict[str, object] = {
        "status": "ready" if ready_now else "not_ready",
        "processed": consumer.processed,
        "errors": consumer.errors,
        "kafka_enabled": settings.enable_kafka,
        "poll_findings": settings.poll_findings,
        "antares_endpoint_set": bool((settings.antares_endpoint or "").strip()),
        "human_review_required": True,
        "autonomous_remediation": False,
        "api_key_configured": api_key_configured,
        "incident_api_service_key_configured": incident_key_configured,
    }
    if consumer.last_error:
        payload["error"] = consumer.last_error
    return payload


@app.post("/api/v1/code/enrich")
def enrich_endpoint(
    body: EnrichmentRequest, _: None = Depends(require_api_key)
) -> Any:
    """Run Antares plan (+ optional tool query/sweep) and post evidence to incident-api."""
    try:
        result = enrich_code(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    consumer.processed += 1
    if result.get("status") == "failed_to_persist":
        consumer.errors += 1
        return JSONResponse(status_code=502, content=result)
    return result


def run() -> None:
    import uvicorn

    uvicorn.run("code_enrichment_worker.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
