from contextlib import asynccontextmanager
from pathlib import Path
import secrets
import shutil
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from code_processor.config import settings
from code_processor.kafka_io import CodeConsumer
from code_processor.pipeline import process_code_change
from code_processor.request_limits import RequestBodyLimitMiddleware
from code_processor.webhook import router as webhook_router

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("code-processor")
except ImportError:
    pass

consumer = CodeConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Optional kafka consumer for code.raw (no-op when CODE_PROCESSOR_ENABLE_KAFKA=false).
    consumer.start()
    yield
    consumer.stop()


app = FastAPI(title="Code Processor", version="0.1.0", lifespan=lifespan)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=16 * 1024 * 1024)
app.include_router(webhook_router)


class CodeProcessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[dict[str, Any]] | None = Field(default=None, min_length=1, max_length=500)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    asset_id: str | None = Field(default=None, min_length=1, max_length=256)
    asset: dict[str, Any] | None = None
    provider: str | None = Field(default=None, max_length=64)
    diff: str | None = Field(default=None, max_length=8 * 1024 * 1024)
    patch: str | None = Field(default=None, max_length=8 * 1024 * 1024)
    diff_text: str | None = Field(default=None, max_length=8 * 1024 * 1024)
    files: dict[str, str] | None = Field(default=None, max_length=10_000)

    @model_validator(mode="after")
    def validate_mode(self) -> "CodeProcessRequest":
        single = any(value is not None for value in (self.diff, self.patch, self.diff_text, self.files))
        if self.events is not None and single:
            raise ValueError("events batch cannot be combined with a single code change")
        if self.events is None and not single:
            raise ValueError("events or code change content is required")
        return self


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not settings.api_key:
        raise HTTPException(status_code=503, detail="processor API key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    semgrep_ready = not settings.semgrep_enabled or shutil.which("semgrep") is not None
    codeql_ready = not settings.codeql_enabled or Path(settings.codeql_cli_path).is_file()
    dependencies_ready = semgrep_ready and codeql_ready
    ready_now = bool(settings.api_key) and (consumer.ready or not settings.enable_kafka) and dependencies_ready
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    payload: dict[str, object] = {
        "status": "ready" if ready_now else "not_ready",
        "api_key_configured": bool(settings.api_key),
        "processed": consumer.pipeline.processed,
        "published": consumer.pipeline.published,
        "errors": consumer.pipeline.errors,
        "kafka_enabled": settings.enable_kafka,
        "scanners": {
            "semgrep": "ready" if semgrep_ready else "unavailable",
            "codeql": "disabled" if not settings.codeql_enabled else (
                "ready" if codeql_ready else "unavailable"
            ),
        },
    }
    if consumer.last_error:
        payload["error"] = consumer.last_error
    return payload


@app.post("/v1/process")
def process_batch(body: CodeProcessRequest, _: None = Depends(require_api_key)) -> dict[str, object]:
    """Process code change events for tests and synchronous callers."""
    payload = body.model_dump(exclude_none=True)
    if body.events is None:
        result = process_code_change(payload)
        return {"features": [result["feature"]], "findings": [result["finding"]], **result}
    features, findings = consumer.process_batch(body.events)
    return {"features": features, "findings": findings}


def run() -> None:
    import uvicorn

    uvicorn.run("code_processor.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
