from contextlib import asynccontextmanager

from fastapi import FastAPI, Response, status

from smoke_consumer.config import settings
from smoke_consumer.consumer import SmokeConsumer
from smoke_consumer.db import count_events, init_db

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("smoke-consumer")
except ImportError:
    pass

consumer = SmokeConsumer()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    consumer.start()
    yield
    await consumer.stop()


app = FastAPI(title="Smoke Consumer", version="0.1.0", lifespan=lifespan)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "ready" if consumer.ready else "not_ready",
        "processed": consumer.processed,
        "inserted": consumer.inserted,
        "stored_rows": count_events(),
    }
    if consumer.last_error:
        payload["error"] = consumer.last_error
    if not consumer.ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload


def run() -> None:
    import uvicorn

    uvicorn.run("smoke_consumer.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
