from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from incident_api import models  # noqa: F401
from incident_api.api import router as incidents_router
from incident_api.config import settings
from incident_api.db import ensure_schema, get_db
from incident_api.deployment_consumer import deployment_consumer
from incident_api.findings import router as findings_router
from incident_api.federated_hunt import router as federated_hunt_router
from incident_api.hunt import router as hunt_router
from incident_api.ops import router as ops_router
from incident_api.operations_api import router as operations_router
from incident_api.profiles_api import router as profiles_router
from incident_api.schemas import HealthDependencies
from incident_api.search import router as search_router
from incident_api.vector_api import router as vector_router

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("incident-api")
except ImportError:
    pass


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from black_onyx_contracts.demo_keys import assert_no_demo_keys

    assert_no_demo_keys(
        service="incident-api",
        keys={
            "INCIDENT_API_SERVICE_KEY": settings.service_api_key,
            "THREAT_INTEL_SERVICE_KEY": settings.threat_intel_service_key,
            "MINIO_ACCESS_KEY": settings.minio_access_key,
            "MINIO_SECRET_KEY": settings.minio_secret_key,
        },
    )
    ensure_schema(
        {
            "incidents",
            "findings",
            "incident_findings",
            "incident_timeline",
            "deployment_events",
            "saved_hunts",
            "analyst_feedback",
            "notification_settings",
            "operational_audit",
        }
    )
    await deployment_consumer.start()
    try:
        yield
    finally:
        await deployment_consumer.stop()


app = FastAPI(title="Incident API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(incidents_router)
app.include_router(findings_router)
app.include_router(search_router)
app.include_router(hunt_router)
app.include_router(federated_hunt_router)
app.include_router(vector_router)
app.include_router(ops_router)
app.include_router(operations_router)
app.include_router(profiles_router)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "error": str(exc)}
    if settings.deployment_consumer_enabled and not deployment_consumer.ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "error": deployment_consumer.last_error or "deployment consumer is starting",
        }
    return {"status": "ready"}


@app.get("/health/dependencies", response_model=HealthDependencies)
def dependencies(
    response: Response,
    db: Session = Depends(get_db),
) -> HealthDependencies:
    db_status = "ok"
    overall = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        db_status = f"error: {exc}"
        overall = "degraded"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    oidc = {
        "disabled": settings.oidc_disabled,
        "issuer": settings.oidc_issuer or None,
        "audience": settings.oidc_audience or None,
    }
    return HealthDependencies(status=overall, database=db_status, oidc=oidc)


def run() -> None:
    import uvicorn

    uvicorn.run("incident_api.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
