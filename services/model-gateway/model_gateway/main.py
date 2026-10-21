from __future__ import annotations



import logging
import secrets
import asyncio

from typing import Any, Literal

from uuid import uuid4



import httpx

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Response, status

from pydantic import BaseModel, ConfigDict, Field



from model_gateway.config import settings

from model_gateway.routing import base_url_for_model, predict_url, select_alias_for_request
from model_gateway.serving_state import effective_alias as confirmed_alias
from model_gateway.serving_state import serving_aliases, verify_version

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("model-gateway")
except ImportError:
    pass

logger = logging.getLogger("model-gateway")



app = FastAPI(title="Model Gateway", version="0.1.0")





class PredictRequest(BaseModel):

    model_config = ConfigDict(protected_namespaces=(), extra="forbid")



    model_name: Literal[
        "log-model", "code-model", "network-model", "metrics-model", "host-state-model"
    ]

    tenant_id: str = Field(min_length=1, max_length=128)

    alias: Literal["champion", "canary", "shadow"] | None = None

    features: dict[str, Any] = Field(default_factory=dict)

    batch: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)

    request_id: str | None = None

    feature_version: str | None = None

    items: list[dict[str, Any]] | None = Field(default=None, max_length=1000)

    model_request: dict[str, Any] | None = None





def build_upstream_payload(body: PredictRequest) -> dict[str, Any]:

    """Merge gateway fields into a model-native predict payload."""

    for source in (body.features, body.model_request or {}):
        if "tenant_id" in source and source["tenant_id"] != body.tenant_id:
            raise ValueError("tenant_id conflicts with gateway request")

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


    # The top-level request is the routing and attribution authority. Matching
    # copies in legacy native bodies remain accepted, but cannot replace it.
    upstream["tenant_id"] = body.tenant_id



    upstream.setdefault("alias", "champion")

    return upstream





async def _post_predict(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:

    async with httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=False) as client:

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


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    expected = settings.api_key.strip()
    if not expected:
        raise HTTPException(status_code=503, detail="model gateway API key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")





@app.get("/health/ready")
async def ready(response: Response) -> dict[str, object]:

    models = {

        "log-model": settings.log_model_url,

        "code-model": settings.code_model_url,

        "network-model": settings.network_model_url,

        "metrics-model": settings.metrics_model_url,
        "host-state-model": settings.host_state_model_url,

    }

    configured = bool(
        settings.api_key.strip()
        and settings.training_orchestrator_url.strip()
        and settings.training_api_key.strip()
        and settings.serving_tenant.strip()
        and all(str(url).strip() for url in models.values())
    )
    aliases_by_model: dict[str, dict[str, Any] | None] = {}
    if configured:
        results = await asyncio.gather(
            *(serving_aliases(name, settings.serving_tenant) for name in models),
            return_exceptions=True,
        )
        aliases_by_model = {
            name: result if isinstance(result, dict) else None
            for name, result in zip(models, results, strict=True)
        }
    serving: dict[str, dict[str, object]] = {}
    for name, aliases in aliases_by_model.items():
        champion = (aliases or {}).get("champion")
        confirmed = confirmed_alias("champion", aliases) == "champion"
        serving[name] = {
            "confirmed": confirmed,
            "version": champion.get("version") if confirmed and champion else None,
            "generation": champion.get("generation") if confirmed and champion else None,
        }
    ready_now = configured and len(serving) == len(models) and all(
        state["confirmed"] for state in serving.values()
    )
    if not ready_now:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready_now else "not_ready",
        "models": models,
        "serving": serving,
        "canary_percent": settings.canary_percent,
        "api_key_configured": bool(settings.api_key.strip()),
        "serving_state_configured": bool(
            settings.training_orchestrator_url.strip()
            and settings.training_api_key.strip()
            and settings.serving_tenant.strip()
        ),
    }





@app.post("/v1/predict")

async def predict(
    body: PredictRequest,
    background: BackgroundTasks,
    _: None = Depends(require_api_key),
) -> dict[str, Any]:

    try:

        base_url_for_model(body.model_name)

    except ValueError as exc:

        raise HTTPException(status_code=400, detail=str(exc)) from exc



    effective_alias = select_alias_for_request(body.alias, body.tenant_id)

    # Shadow mode: serve champion response and fire-and-forget shadow.

    serving_alias = "champion" if effective_alias == "shadow" else effective_alias
    aliases = await serving_aliases(body.model_name, body.tenant_id)
    serving_alias = confirmed_alias(serving_alias, aliases)
    if serving_alias is None:
        raise HTTPException(status_code=503, detail="no freshly confirmed serving alias is available")

    url = predict_url(body.model_name, serving_alias)

    try:
        payload = build_upstream_payload(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    payload["alias"] = serving_alias



    try:

        result = await _post_predict(url, payload, settings.request_timeout_seconds)

    except httpx.HTTPError as exc:

        raise HTTPException(status_code=502, detail=f"upstream model error: {exc}") from exc



    shadow_target = (aliases or {}).get("shadow")
    if (effective_alias == "shadow" or body.alias == "shadow") and shadow_target and shadow_target.get("confirmed"):

        shadow_payload = {**payload, "alias": "shadow"}

        background.add_task(_shadow_call, body.model_name, shadow_payload)



    result = dict(result)

    result.setdefault("routed_alias", serving_alias)

    result.setdefault("requested_alias", body.alias or "auto")

    result.setdefault("model_name", body.model_name)
    serving = verify_version(serving_alias, result, aliases)
    if serving["expected_version"] is not None and not serving["version_verified"]:
        raise HTTPException(status_code=502, detail="model replica served a version outside confirmed serving state")
    result["serving"] = serving
    return result





def run() -> None:

    import uvicorn



    uvicorn.run("model_gateway.main:app", host=settings.host, port=settings.port, reload=False)





if __name__ == "__main__":

    run()

