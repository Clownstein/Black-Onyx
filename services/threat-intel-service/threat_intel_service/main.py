"""Threat intel FastAPI application."""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from threat_intel_service.config import settings
from threat_intel_service.db import engine, ensure_schema, get_db
from threat_intel_service.enrich import build_match_result, match_result_to_dict
from threat_intel_service.ingest import kev, misp, stix_upload, taxii
from threat_intel_service.semantic import semantic_match
from threat_intel_service.request_limits import RequestBodyLimitMiddleware
from threat_intel_service.store import expire_stale, list_feed_health, list_indicators, match_observables


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_schema()
    yield


app = FastAPI(title="Threat Intel Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=16 * 1024 * 1024)

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("threat-intel-service")
except Exception:
    pass


class ObservableIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=4096)


class MatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observables: list[ObservableIn] = Field(default_factory=list, max_length=500)


class SemanticMatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observables: list[ObservableIn] = Field(default_factory=list, max_length=100)
    top_k: int = Field(default=10, ge=1, le=100)
    min_similarity: float = Field(default=0.1, ge=0.0, le=1.0)


def _airgap_blocked() -> None:
    if settings.airgap_mode:
        raise HTTPException(
            status_code=403,
            detail="Outbound feed sync disabled in airgap_mode; use STIX upload instead",
        )


def require_service_key(
    x_service_key: str | None = Header(default=None, alias="X-Service-Key"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    expected = (settings.service_api_key or "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="service key is not configured")
    provided = x_service_key or x_api_key
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="invalid or missing service key")


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    with engine.connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    configured = bool((settings.service_api_key or "").strip())
    response = {
        "status": "ready" if configured else "not_ready",
        "api_key_configured": configured,
        "airgap_mode": settings.airgap_mode,
    }
    if not configured:
        return JSONResponse(status_code=503, content=response)
    return response


@app.post("/api/v1/indicators/upload-stix")
def upload_stix(
    bundle: dict[str, Any],
    db: Session = Depends(get_db),
    _: None = Depends(require_service_key),
) -> dict[str, Any]:
    try:
        return stix_upload.ingest_stix_bundle(db, bundle)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/feeds/kev/sync")
async def sync_kev(
    db: Session = Depends(get_db),
    _: None = Depends(require_service_key),
) -> dict[str, Any]:
    _airgap_blocked()
    try:
        return await kev.sync_kev(db)
    except Exception as exc:  # Feed adapter persists health before re-raising.
        return JSONResponse(
            status_code=502,
            content={
                "status": "degraded",
                "capability": "kev_sync",
                "reason": str(exc),
                "retry_after_seconds": 60,
            },
        )


@app.post("/api/v1/feeds/taxii/sync")
async def sync_taxii(
    db: Session = Depends(get_db),
    _: None = Depends(require_service_key),
) -> dict[str, Any]:
    _airgap_blocked()
    try:
        return await taxii.sync_taxii(db)
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={
                "status": "degraded",
                "capability": "taxii_sync",
                "reason": str(exc),
                "retry_after_seconds": 60,
            },
        )


@app.post("/api/v1/feeds/misp/sync")
async def sync_misp(
    db: Session = Depends(get_db),
    _: None = Depends(require_service_key),
) -> dict[str, Any]:
    _airgap_blocked()
    try:
        return await misp.sync_misp(db)
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={
                "status": "degraded",
                "capability": "misp_sync",
                "reason": str(exc),
                "retry_after_seconds": 60,
            },
        )


@app.post("/api/v1/match")
def match(
    body: MatchRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
    _: None = Depends(require_service_key),
) -> dict[str, Any]:
    expire_stale(db)
    rows = match_observables(
        db,
        [{"type": o.type, "value": o.value} for o in body.observables],
        tenant_id=x_tenant_id,
    )
    result = build_match_result(rows)
    return match_result_to_dict(result)


@app.post("/api/v1/match/semantic")
def match_semantic(
    body: SemanticMatchRequest,
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
    db: Session = Depends(get_db),
    _: None = Depends(require_service_key),
) -> dict[str, Any]:
    """Approximate similarity match.

    Advisory only: hits are capped at ``semantic_max_confidence`` and tagged
    ``match_type="semantic"``. When ``VECTOR_SEARCH_ENABLED`` is false, returns
    no matches plus a warning.
    """
    expire_stale(db)
    return semantic_match(
        db,
        [{"type": o.type, "value": o.value} for o in body.observables],
        enabled=settings.vector_search_enabled,
        max_confidence=settings.semantic_max_confidence,
        top_k=body.top_k,
        min_similarity=body.min_similarity,
        qdrant_url=settings.qdrant_url,
        tenant_id=x_tenant_id,
    )


@app.get("/api/v1/indicators")
def get_indicators(
    q: str | None = Query(default=None, max_length=512),
    type: str | None = Query(default=None, alias="type", max_length=64),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
    _: None = Depends(require_service_key),
) -> dict[str, Any]:
    rows = list_indicators(db, q=q, observable_type=type, tenant_id=x_tenant_id)
    return {
        "indicators": [
            {
                "indicator_id": r.indicator_id,
                "tenant_id": r.tenant_id,
                "observable_type": r.observable_type,
                "observable_value": r.observable_value,
                "source": r.source,
                "confidence": r.confidence,
                "tlp": r.tlp,
                "valid_from": r.valid_from.isoformat() if r.valid_from else None,
                "valid_until": r.valid_until.isoformat() if r.valid_until else None,
                "labels": r.labels or [],
                "campaigns": r.campaigns or [],
                "mitre_techniques": r.mitre_techniques or [],
            }
            for r in rows
        ]
    }


class IndicatorUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observable_type: str = Field(min_length=1, max_length=64)
    observable_value: str = Field(min_length=1, max_length=4096)
    source: str = Field(default="black-onyx-tip", min_length=1, max_length=128)
    confidence: int = Field(default=70, ge=0, le=100)
    tlp: str | None = Field(default="amber", max_length=32)
    tenant_id: str | None = Field(default=None, max_length=128)
    labels: list[str] = Field(default_factory=list, max_length=100)


class IndicatorUpsertBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicators: list[IndicatorUpsert] = Field(min_length=1, max_length=500)


@app.post("/api/v1/indicators/upsert")
def upsert_indicators(
    body: IndicatorUpsertBatch,
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
    db: Session = Depends(get_db),
    _: None = Depends(require_service_key),
) -> dict[str, Any]:
    """Upsert TIP-published / analyst indicators into the match-on-wire SoR."""
    from threat_intel_service.store import upsert_indicator

    upserted = 0
    for item in body.indicators:
        if item.tenant_id is not None and item.tenant_id != x_tenant_id:
            raise HTTPException(status_code=403, detail="tenant header/body mismatch")
        upsert_indicator(
            db,
            {
                "observable_type": item.observable_type,
                "observable_value": item.observable_value,
                "source": item.source,
                "confidence": item.confidence,
                "tlp": item.tlp,
                "tenant_id": x_tenant_id,
                "labels": list(item.labels or []) + ["tip-sync"],
            },
        )
        upserted += 1
    db.commit()
    return {"status": "ok", "upserted": upserted}


@app.get("/api/v1/feeds/health")
def feeds_health(
    db: Session = Depends(get_db),
    _: None = Depends(require_service_key),
) -> dict[str, Any]:
    return {"feeds": list_feed_health(db)}


def run() -> None:
    import uvicorn

    uvicorn.run("threat_intel_service.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
