"""Integration hub vuln ingest, SIEM export, TheHive, response approvals, DFIR."""

from __future__ import annotations

import secrets
import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from integration_hub import response_client
from integration_hub.config import settings
from integration_hub.db import engine, ensure_schema, get_db
from integration_hub.dfir import queue_collect
from integration_hub.findings_persist import persist_findings
from integration_hub.models import TheHiveDryRun
from integration_hub.request_limits import RequestBodyLimitMiddleware
from integration_hub.siem import format_siem_export
from integration_hub.thehive import create_or_update_case
from integration_hub.threat_intel_client import match_cves
from integration_hub.hr import evaluate_identity_checks, parse_hr_csv, parse_hr_webhook
from integration_hub.idp import normalize_entra_users, normalize_okta_users
from integration_hub.vuln import _extract_cve, extract_vulnerabilities, vulnerability_to_finding

try:
    from black_onyx_otel import setup_tracing

    setup_tracing("integration-hub")
except Exception:
    pass


def _check_api_key(x_api_key: str | None) -> None:
    expected = settings.api_key
    if not expected:
        raise HTTPException(status_code=503, detail="integration API key is not configured")
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    _check_api_key(x_api_key)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_schema()
    yield


app = FastAPI(title="Integration Hub", version="0.1.0", lifespan=lifespan)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=16 * 1024 * 1024)


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VulnIngestRequest(StrictRequest):
    tenant_id: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=256)
    scanner: str | None = Field(default=None, max_length=64)
    report: dict[str, Any] = Field(min_length=1, max_length=4096)


class SiemExportRequest(StrictRequest):
    format: Literal["json", "cef"] = "json"
    incident: dict[str, Any] = Field(min_length=1, max_length=256)


class TheHiveCaseRequest(StrictRequest):
    incident: dict[str, Any] = Field(min_length=1, max_length=256)
    case_id: str | None = Field(default=None, max_length=256)


class ResponseRequestBody(StrictRequest):
    tenant_id: str = Field(min_length=1, max_length=128)
    incident_id: str = Field(min_length=1, max_length=128)
    playbook_id: str = Field(min_length=1, max_length=128)
    action: Literal["execute"] = "execute"
    dry_run: bool = True
    payload: dict[str, Any] = Field(default_factory=dict, max_length=256)
    actor: str = Field(min_length=1, max_length=254)


class ApproveBody(StrictRequest):
    actor: str = Field(min_length=1, max_length=254)
    dry_run: bool | None = None


class DfirCollectBody(StrictRequest):
    tenant_id: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=256)
    artifact: str = Field(default="Generic.Client.Info", min_length=1, max_length=256)
    incident_id: str | None = Field(default=None, max_length=128)
    dry_run: bool = True
    detail: dict[str, Any] = Field(default_factory=dict, max_length=256)
    notes: str | None = Field(default=None, max_length=4096)


def _resolve_report(body: VulnIngestRequest) -> dict[str, Any]:
    return body.report


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready(response: Response) -> dict[str, object]:
    with engine.connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    configured = bool(settings.api_key)
    if not configured:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if configured else "not_ready",
        "thehive_configured": bool(settings.thehive_url and settings.thehive_key),
        "velociraptor_configured": bool(settings.velociraptor_url),
        "pfsense_configured": bool(settings.pfsense_api_url),
        "edr_configured": bool(settings.edr_api_url),
        "api_key_configured": configured,
    }


@app.post("/api/v1/vuln/ingest")
async def vuln_ingest(
    body: VulnIngestRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> dict[str, Any]:
    """Accept Trivy/Grype-like JSON and normalize to vulnerability findings."""
    _check_api_key(x_api_key)
    if x_tenant_id and x_tenant_id != body.tenant_id:
        raise HTTPException(status_code=403, detail="X-Tenant-Id does not match body tenant_id")
    tenant_id = body.tenant_id
    payload = _resolve_report(body)
    vulns = extract_vulnerabilities(payload)
    cves = [c for c in (_extract_cve(v) for v in vulns) if c]
    ti_hits = await match_cves(cves)

    findings: list[dict[str, Any]] = []
    kev_boosted = 0
    for item in vulns:
        if body.scanner and not item.get("_scanner"):
            item["_scanner"] = body.scanner
        cve = _extract_cve(item)
        ti = ti_hits.get(cve or "", {})
        boost = bool(ti)
        if boost:
            kev_boosted += 1
        findings.append(
            vulnerability_to_finding(
                item,
                tenant_id=tenant_id,
                asset_id=body.asset_id,
                kev_boost=boost,
                kev_boost_amount=settings.kev_score_boost,
                threat_intel={"matches": [ti]} if ti else {},
            )
        )

    return {
        "tenant_id": tenant_id,
        "asset_id": body.asset_id,
        "vulnerability_count": len(vulns),
        "findings_count": len(findings),
        "kev_boosted": kev_boosted,
        "findings": findings,
        "persist": await persist_findings(findings),
    }


@app.post("/api/v1/integrations/siem/export")
def siem_export(
    body: SiemExportRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> dict[str, Any]:
    """Format an incident as JSON object or CEF string for SIEM outbound."""
    _check_api_key(x_api_key)
    if not body.incident:
        raise HTTPException(status_code=400, detail="incident is required")
    tenant_id = body.incident.get("tenant_id")
    incident_id = body.incident.get("incident_id") or body.incident.get("id")
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-Id required")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise HTTPException(status_code=422, detail="incident.tenant_id required")
    if tenant_id != x_tenant_id:
        raise HTTPException(status_code=403, detail="tenant header/body mismatch")
    if not isinstance(incident_id, str) or not incident_id.strip():
        raise HTTPException(status_code=422, detail="incident.incident_id required")
    fmt = body.format or settings.siem_default_format
    return format_siem_export(
        body.incident,
        fmt=fmt,
        device_vendor=settings.siem_device_vendor,
        device_product=settings.siem_device_product,
        device_version=settings.siem_device_version,
    )


@app.post("/api/v1/thehive/cases")
def thehive_case(
    body: TheHiveCaseRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    tenant_id = body.incident.get("tenant_id")
    incident_id = body.incident.get("incident_id") or body.incident.get("id")
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-Id required")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise HTTPException(status_code=422, detail="incident.tenant_id required")
    if tenant_id != x_tenant_id:
        raise HTTPException(status_code=403, detail="tenant header/body mismatch")
    if not isinstance(incident_id, str) or not incident_id.strip():
        raise HTTPException(status_code=422, detail="incident.incident_id required")
    try:
        return create_or_update_case(db, body.incident, case_id=body.case_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/v1/thehive/dry-runs")
def list_thehive_dry_runs(
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
    limit: int = Query(default=50, ge=1, le=500),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> dict[str, Any]:
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-Id required")
    rows = (
        db.query(TheHiveDryRun)
        .filter(TheHiveDryRun.tenant_id == x_tenant_id)
        .order_by(TheHiveDryRun.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "items": [
            {
                "id": r.id,
                "tenant_id": r.tenant_id,
                "incident_id": r.incident_id,
                "operation": r.operation,
                "payload": r.payload,
            }
            for r in rows
        ]
    }


@app.post("/api/v1/response/request")
def response_request(
    body: ResponseRequestBody,
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return response_client.create_request(body.model_dump())
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=exc.response.status_code,
            detail=exc.response.text,
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "degraded",
                "capability": "response_orchestration",
                "reason": str(exc),
                "retry_after_seconds": 5,
            },
        ) from exc


@app.post("/api/v1/response/{request_id}/approve")
def response_approve(
    request_id: str,
    body: ApproveBody,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-Id required")
    try:
        return response_client.approve_request(
            request_id=request_id,
            tenant_id=x_tenant_id,
            actor=body.actor,
            dry_run=body.dry_run,
        )
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=exc.response.status_code,
            detail=exc.response.text,
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/v1/response/audit")
def response_audit(
    _: None = Depends(require_api_key),
    tenant_id: str | None = Query(default=None),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-Id required")
    if tenant_id is not None and tenant_id != x_tenant_id:
        raise HTTPException(status_code=403, detail="tenant_id does not match X-Tenant-Id")
    resolved_tenant = x_tenant_id
    try:
        return response_client.list_audit(resolved_tenant, limit)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=exc.response.status_code,
            detail=exc.response.text,
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/v1/dfir/collect")
def dfir_collect(
    body: DfirCollectBody,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    row = queue_collect(
        db,
        tenant_id=body.tenant_id,
        asset_id=body.asset_id,
        artifact=body.artifact,
        incident_id=body.incident_id,
        dry_run=body.dry_run,
        detail=body.detail,
        notes=body.notes,
    )
    return {
        "request_id": row.request_id,
        "status": row.status,
        "dry_run": row.dry_run,
        "asset_id": row.asset_id,
        "artifact": row.artifact,
        "detail": row.detail,
        "message": (
            "Collection queued (dry-run)"
            if row.dry_run
            else (
                "Collection submitted to Velociraptor"
                if row.status == "submitted"
                else "Collection failed; Velociraptor did not accept the request"
            )
        ),
    }


class IdpSyncRequest(StrictRequest):
    provider: Literal["entra", "okta"] = "entra"
    payload: dict[str, Any] | list[Any] = Field(default_factory=dict, max_length=10_000)


class HrSyncRequest(StrictRequest):
    format: Literal["csv", "json"] = "csv"
    csv_text: str | None = Field(default=None, max_length=8 * 1024 * 1024)
    payload: dict[str, Any] | None = Field(default=None, max_length=10_000)


class IdentityEvaluateRequest(StrictRequest):
    tenant_id: str = Field(min_length=1, max_length=128)
    idp_users: list[dict[str, Any]] = Field(default_factory=list, max_length=10_000)
    hr_employees: list[dict[str, Any]] = Field(default_factory=list, max_length=10_000)


@app.post("/api/v1/identity/idp/sync")
def idp_sync(
    body: IdpSyncRequest,
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    users = (
        normalize_entra_users(body.payload)
        if body.provider == "entra"
        else normalize_okta_users(body.payload)
    )
    return {"provider": body.provider, "users": users, "count": len(users)}


@app.post("/api/v1/identity/hr/sync")
def hr_sync(
    body: HrSyncRequest,
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    if body.format == "csv":
        employees = parse_hr_csv(body.csv_text or "")
    else:
        employees = parse_hr_webhook(body.payload or {})
    return {"employees": employees, "count": len(employees)}


@app.post("/api/v1/identity/evaluate")
async def identity_evaluate(
    body: IdentityEvaluateRequest,
    x_tenant_id: str = Header(alias="X-Tenant-Id", min_length=1, max_length=128),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    if x_tenant_id != body.tenant_id:
        raise HTTPException(status_code=403, detail="tenant header/body mismatch")
    findings = evaluate_identity_checks(body.idp_users, body.hr_employees)
    now = datetime.now(UTC).isoformat()
    canonical_findings: list[dict[str, Any]] = []
    for finding in findings:
        check_id = str(finding.get("check_id") or "identity.unknown")
        email = str(finding.get("email") or "unknown").strip().casefold()
        identity = f"{body.tenant_id}\0{check_id}\0{email}"
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        score = 0.5 if finding.get("status") == "unknown" else 0.8
        severity = "medium" if finding.get("status") == "unknown" else "high"
        canonical_findings.append({
            "finding_id": f"identity-{digest[:48]}",
            "tenant_id": body.tenant_id,
            "finding_type": "identity",
            "asset_id": f"identity:{email}"[:256],
            "model_name": "integration-hub-identity",
            "model_version": "1.0",
            "feature_version": "1.0",
            "raw_score": score,
            "calibrated_score": score,
            "severity_hint": severity,
            "window": {"start": now, "end": now},
            "contributors": [{
                "type": "identity_check",
                "contribution": score,
                "summary": str(finding.get("detail") or check_id)[:1024],
            }],
            "evidence_refs": [],
            "context": {
                "check_id": check_id,
                "email": email,
                "detail": str(finding.get("detail") or "")[:2048],
                "status": finding.get("status"),
                "compliance": finding.get("compliance") or {},
            },
            "fingerprint": f"identity:{digest}",
            "category": ["identity", check_id],
            "schema_version": "1.0",
        })
    persisted = await persist_findings(canonical_findings)
    return {"findings": findings, "count": len(findings), "persistence": persisted}


def run() -> None:
    import uvicorn

    uvicorn.run("integration_hub.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
