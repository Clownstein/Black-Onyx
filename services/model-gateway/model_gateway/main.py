from __future__ import annotations



import logging

from typing import Any

from uuid import uuid4



import httpx

from fastapi import BackgroundTasks, FastAPI, HTTPException

from pydantic import BaseModel, ConfigDict, Field



from model_gateway.config import settings

from model_gateway.routing import base_url_for_model, predict_url, select_alias_for_request

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("model-gateway")
except ImportError:
    pass

logger = logging.getLogger("model-gateway")



app = FastAPI(title="Model Gateway", version="0.1.0")





class PredictRequest(BaseModel):

    model_config = ConfigDict(protected_namespaces=(), extra="allow")



    model_name: str

    tenant_id: str

    alias: str | None = None

    features: dict[str, Any] = Field(default_factory=dict)

    batch: list[dict[str, Any]] = Field(default_factory=list)

    request_id: str | None = None

    feature_version: str | None = None

    items: list[dict[str, Any]] | None = None

    model_request: dict[str, Any] | None = None





def build_upstream_payload(body: PredictRequest) -> dict[str, Any]:

    """Merge gateway fields into a model-native predict payload."""

    upstream: dict[str, Any] = {

        "request_id": body.request_id or str(uuid4()),

        "tenant_id": body.tenant_id,

        "model_name": body.model_name,

        "feature_version": body.feature_version or "1.0",

        **body.features,

    }



    # Prefer explicit model_request for native field shapes (network/metrics/code).

    if body.model_request:

        upstream.update(body.model_request)



    if body.batch:

        upstream["items"] = body.batch

    if body.items is not None:

        upstream["items"] = body.items



    # Pass through any additional known top-level extras (e.g. flows, values).

    extra = body.model_extra or {}

    for key, value in extra.items():

        if key in {"alias"}:

            continue

        if value is not None and key not in upstream:

            upstream[key] = value



    upstream.setdefault("alias", "champion")

    return upstream





async def _post_predict(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:

    async with httpx.AsyncClient(timeout=timeout) as client:

        response = await client.post(url, json=payload)

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):

            return {"result": data}

        return data





async def _shadow_call(model_name: str, payload: dict[str, Any]) -> None:

    url = predict_url(model_name, "shadow")

    try:

        await _post_predict(url, payload, settings.shadow_timeout_seconds)

    except Exception:  # noqa: BLE001 - shadow must never fail the primary request

        logger.exception("shadow predict failed for %s", model_name)





@app.get("/health/live")

def live() -> dict[str, str]:

    return {"status": "alive"}





@app.get("/health/ready")

def ready() -> dict[str, object]:

    models = {

        "log-model": settings.log_model_url,

        "code-model": settings.code_model_url,

        "network-model": settings.network_model_url,

        "metrics-model": settings.metrics_model_url,

    }

    return {"status": "ready", "models": models, "canary_percent": settings.canary_percent}





@app.post("/v1/predict")

async def predict(body: PredictRequest, background: BackgroundTasks) -> dict[str, Any]:

    try:

        base_url_for_model(body.model_name)

    except ValueError as exc:

        raise HTTPException(status_code=400, detail=str(exc)) from exc



    effective_alias = select_alias_for_request(body.alias, body.tenant_id)

    # Shadow mode: serve champion response and fire-and-forget shadow.

    serving_alias = "champion" if effective_alias == "shadow" else effective_alias

    url = predict_url(body.model_name, serving_alias)

    payload = build_upstream_payload(body)

    payload["alias"] = serving_alias



    try:

        result = await _post_predict(url, payload, settings.request_timeout_seconds)

    except httpx.HTTPError as exc:

        raise HTTPException(status_code=502, detail=f"upstream model error: {exc}") from exc



    if effective_alias == "shadow" or body.alias == "shadow":

        shadow_payload = {**payload, "alias": "shadow"}

        background.add_task(_shadow_call, body.model_name, shadow_payload)



    result = dict(result)

    result.setdefault("routed_alias", serving_alias)

    result.setdefault("requested_alias", body.alias or "auto")

    result.setdefault("model_name", body.model_name)

    return result





def run() -> None:

    import uvicorn



    uvicorn.run("model_gateway.main:app", host=settings.host, port=settings.port, reload=False)





if __name__ == "__main__":

    run()

