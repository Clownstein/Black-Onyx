from contextlib import asynccontextmanager

from fastapi import FastAPI

from training_orchestrator.api import router
from training_orchestrator.config import settings
from training_orchestrator.db import engine, ensure_schema

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("training-orchestrator")
except ImportError:
    pass


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_schema()
    yield


app = FastAPI(title="Training Orchestrator", version="0.1.0", lifespan=lifespan)
app.include_router(router)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, str]:
    with engine.connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    return {"status": "ready"}


def run() -> None:
    import uvicorn

    uvicorn.run("training_orchestrator.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
