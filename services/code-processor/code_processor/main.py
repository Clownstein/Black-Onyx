from contextlib import asynccontextmanager
from pathlib import Path
import shutil

from fastapi import FastAPI, Response, status

from code_processor.config import settings
from code_processor.kafka_io import CodeConsumer
from code_processor.pipeline import process_code_change
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
app.include_router(webhook_router)


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
    ready_now = (consumer.ready or not settings.enable_kafka) and dependencies_ready
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    payload: dict[str, object] = {
        "status": "ready" if ready_now else "not_ready",
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
def process_batch(body: dict) -> dict[str, object]:
    """Process code change events for tests and synchronous callers."""
    if "diff" in body or "patch" in body or "diff_text" in body or "files" in body:
        result = process_code_change(body)
        return {"features": [result["feature"]], "findings": [result["finding"]], **result}
    events = body.get("events") or []
    features, findings = consumer.process_batch(events)
    return {"features": features, "findings": findings}


def run() -> None:
    import uvicorn

    uvicorn.run("code_processor.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
