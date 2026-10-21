from contextlib import asynccontextmanager

from fastapi import FastAPI

from log_processor.config import settings
from log_processor.consumer import LogProcessorWorker

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("log-processor")
except ImportError:
    pass

worker = LogProcessorWorker()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    worker.start()
    yield
    await worker.stop()


app = FastAPI(title="Log Processor", version="0.1.0", lifespan=lifespan)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    status = "ready" if worker.ready else "not_ready"
    body: dict[str, object] = {
        "status": status,
        "processed": worker.processor.processed,
        "published": worker.processor.published,
    }
    if worker.last_error:
        body["last_error"] = worker.last_error
    return body


def run() -> None:
    import uvicorn

    uvicorn.run("log_processor.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
