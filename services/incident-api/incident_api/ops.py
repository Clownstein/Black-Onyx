"""Ops endpoints for UI model catalog and data-plane health."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

import httpx
from fastapi import APIRouter
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

router = APIRouter(prefix="/api/v1/ops", tags=["ops"])

ModelStatus = Literal["ready", "training", "degraded", "offline"]
HealthStatus = Literal["ok", "lagging", "stale", "error"]


class OpsProbeSettings(BaseSettings):
    """Service DNS overrides for in-cluster / Compose probes."""

    model_config = SettingsConfigDict(env_prefix="INCIDENT_API_OPS_", extra="ignore")

    log_model_url: str = "http://localhost:8090/health/live"
    network_model_url: str = "http://localhost:8101/health/live"
    metrics_model_url: str = "http://localhost:8102/health/live"
    code_model_url: str = "http://localhost:8103/health/live"
    ingestion_gateway_url: str = "http://localhost:8080/health/live"
    log_processor_url: str = "http://localhost:8082/health/live"
    flow_processor_url: str = "http://localhost:8094/health/live"
    metrics_processor_url: str = "http://localhost:8095/health/live"
    code_processor_url: str = "http://localhost:8093/health/live"
    inference_worker_url: str = "http://localhost:8088/health/live"
    model_gateway_url: str = "http://localhost:8091/health/live"
    correlation_engine_url: str = "http://localhost:8084/health/live"
    incident_api_url: str = "http://localhost:8083/health/live"
    prometheus_url: str = "http://localhost:9090"


ops_settings = OpsProbeSettings()


def _model_targets() -> list[dict[str, str]]:
    return [
        {
            "model_id": "log-model",
            "name": "Log Anomaly Model",
            "modality": "logs",
            "health_url": ops_settings.log_model_url,
        },
        {
            "model_id": "network-model",
            "name": "Network Flow Anomaly Model",
            "modality": "network",
            "health_url": ops_settings.network_model_url,
        },
        {
            "model_id": "metrics-model",
            "name": "Metrics Anomaly Model",
            "modality": "metrics",
            "health_url": ops_settings.metrics_model_url,
        },
        {
            "model_id": "code-model",
            "name": "Code Risk Model",
            "modality": "code",
            "health_url": ops_settings.code_model_url,
        },
    ]


def _health_targets() -> list[dict[str, str]]:
    return [
        {
            "source_id": "ingestion-gateway",
            "name": "Ingestion Gateway",
            "modality": "ingest",
            "url": ops_settings.ingestion_gateway_url,
        },
        {
            "source_id": "log-processor",
            "name": "Log Processor",
            "modality": "logs",
            "url": ops_settings.log_processor_url,
        },
        {
            "source_id": "flow-processor",
            "name": "Flow Processor",
            "modality": "network",
            "url": ops_settings.flow_processor_url,
        },
        {
            "source_id": "metrics-processor",
            "name": "Metrics Processor",
            "modality": "metrics",
            "url": ops_settings.metrics_processor_url,
        },
        {
            "source_id": "code-processor",
            "name": "Code Processor",
            "modality": "code",
            "url": ops_settings.code_processor_url,
        },
        {
            "source_id": "inference-worker",
            "name": "Inference Worker",
            "modality": "inference",
            "url": ops_settings.inference_worker_url,
        },
        {
            "source_id": "model-gateway",
            "name": "Model Gateway",
            "modality": "models",
            "url": ops_settings.model_gateway_url,
        },
        {
            "source_id": "correlation-engine",
            "name": "Correlation Engine",
            "modality": "correlation",
            "url": ops_settings.correlation_engine_url,
        },
        {
            "source_id": "incident-api",
            "name": "Incident API",
            "modality": "api",
            "url": ops_settings.incident_api_url,
        },
    ]


class ModelInfo(BaseModel):
    model_id: str
    name: str
    modality: str
    version: str = "0.1.0"
    status: ModelStatus = "offline"
    last_inference: str
    findings_24h: int = 0
    avg_latency_ms: float = 0.0
    eval_metrics: dict = Field(default_factory=dict)


class DataHealthSource(BaseModel):
    source_id: str
    name: str
    modality: str
    lag_seconds: float | None = None
    lag_records: float | None = None
    events_per_min: float | None = None
    status: HealthStatus = "error"
    last_event: str | None = None
    capability: str = "operational_data_health"
    reason: str | None = None


def _probe(url: str, timeout: float = 1.5) -> bool:
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url)
            return resp.status_code < 400
    except Exception:  # noqa: BLE001
        return False


def _prometheus_values(query: str) -> list[dict]:
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.get(
                f"{ops_settings.prometheus_url.rstrip('/')}/api/v1/query",
                params={"query": query},
            )
            response.raise_for_status()
            payload = response.json()
        if payload.get("status") != "success":
            return []
        result = payload.get("data", {}).get("result", [])
        return result if isinstance(result, list) else []
    except Exception:  # Optional telemetry dependency is reflected in the response.
        return []


@router.get("/models", response_model=list[ModelInfo])
def list_models() -> list[ModelInfo]:
    now = datetime.now(UTC).isoformat()
    out: list[ModelInfo] = []
    for item in _model_targets():
        ok = _probe(str(item["health_url"]))
        out.append(
            ModelInfo(
                model_id=str(item["model_id"]),
                name=str(item["name"]),
                modality=str(item["modality"]),
                version="0.1.0",
                status="ready" if ok else "offline",
                last_inference=now,
                findings_24h=0,
                avg_latency_ms=12.0 if ok else 0.0,
            )
        )
    return out


@router.get("/models/{model_id}", response_model=ModelInfo)
def get_model(model_id: str) -> ModelInfo:
    for item in list_models():
        if item.model_id == model_id:
            return item
    now = datetime.now(UTC).isoformat()
    return ModelInfo(
        model_id=model_id,
        name=model_id,
        modality="unknown",
        status="offline",
        last_inference=now,
    )


@router.get("/data-health", response_model=list[DataHealthSource])
def data_health() -> list[DataHealthSource]:
    lag_rows = _prometheus_values(
        "max by (group) (anomaly_kafka_consumer_lag_records)"
    )
    lag_by_service: dict[str, float] = {}
    for row in lag_rows:
        try:
            service = str((row.get("metric") or {}).get("group") or "")
            value = float((row.get("value") or [None, None])[1])
        except (TypeError, ValueError, IndexError):
            continue
        if service:
            lag_by_service[service] = value
    rate_rows = _prometheus_values(
        "sum(rate(ingestion_events_accepted_total[5m])) * 60"
    )
    ingestion_rate: float | None = None
    if rate_rows:
        try:
            ingestion_rate = float((rate_rows[0].get("value") or [None, None])[1])
        except (TypeError, ValueError, IndexError):
            ingestion_rate = None
    sources: list[DataHealthSource] = []
    for target in _health_targets():
        ok = _probe(str(target["url"]))
        source_id = str(target["source_id"])
        lag = lag_by_service.get(source_id)
        rate = ingestion_rate if source_id == "ingestion-gateway" else None
        telemetry_available = lag is not None or rate is not None
        sources.append(
            DataHealthSource(
                source_id=source_id,
                name=str(target["name"]),
                modality=str(target["modality"]),
                lag_seconds=None,
                lag_records=lag,
                events_per_min=rate,
                status=(
                    "error"
                    if not ok
                    else "lagging"
                    if lag is not None and lag > 1000
                    else "ok"
                ),
                reason=(
                    None
                    if telemetry_available
                    else "service health available; broker telemetry unavailable"
                ),
            )
        )
    return sources
