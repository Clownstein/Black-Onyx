"""Integration hub — vuln ingest, SIEM export, TheHive, response approvals, DFIR."""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from integration_hub import response_client
from integration_hub.config import settings
from integration_hub.db import engine, ensure_schema, get_db
from integration_hub.dfir import queue_collect
from integration_hub.findings_persist import persist_findings
from integration_hub.models import TheHiveDryRun
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
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    _check_api_key(x_api_key)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_schema()
    yield


app = FastAPI(title="Integration Hub", version="0.1.0", lifespan=lifespan)


class VulnIngestRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    tenant_id: str = Field(default="default", min_length=1)
    asset_id: str = Field(min_length=1)
    scanner: str | None = None
    report: dict[str, Any] | None = None


class SiemExportRequest(BaseModel):
    format: Literal["json", "cef"] = "json"
    incident: dict[str, Any]


class TheHiveCaseRequest(BaseModel):
    incident: dict[str, Any]
    case_id: str | None = None


class ResponseRequestBody(BaseModel):
    tenant_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    playbook_id: str = Field(min_length=1)
    action: str = "execute"
    dry_run: bool = True
    payload: dict[str, Any] = Field(default_factory=dict)
    actor: str = "system"


class ApproveBody(BaseModel):
    actor: str = "approver"
    dry_run: bool | None = None


class DfirCollectBody(BaseModel):
    tenant_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    artifact: str = "Generic.Client.Info"
    incident_id: str | None = None
    dry_run: bool = True
    detail: dict[str, Any] = Field(default_factory=dict)
    notes: str | None = None


def _resolve_report(body: VulnIngestRequest) -> dict[str, Any]:
    if isinstance(body.report, dict) and body.report:
        return body.report
    data = body.model_dump(exclude={"tenant_id", "asset_id", "scanner", "report"})
    return data


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict[str, object]:
    with engine.connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    return {
        "status": "ready",
        "thehive_configured": bool(settings.thehive_url and settings.thehive_key),
        "velociraptor_configured": bool(settings.velociraptor_url),
        "pfsense_configured": bool(settings.pfsense_api_url),
        "edr_configured": bool(settings.edr_api_url),
        "api_key_required": bool(settings.api_key),
    }


@app.post("/api/v1/vuln/ingest")
async def vuln_ingest(
    body: VulnIngestRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> dict[str, Any]:
    """Accept Trivy/Grype-like JSON and normalize to vulnerability findings."""
    _check_api_key(x_api_key)
    tenant_id = x_tenant_id or body.tenant_id or "default"
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
) -> dict[str, Any]:
    """Format an incident as JSON object or CEF string for SIEM outbound."""
    _check_api_key(x_api_key)
    if not body.incident:
        raise HTTPException(status_code=400, detail="incident is required")
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
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return create_or_update_case(db, body.incident, case_id=body.case_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/v1/thehive/dry-runs")
def list_thehive_dry_runs(
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    rows = db.query(TheHiveDryRun).order_by(TheHiveDryRun.id.desc()).limit(limit).all()
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
    resolved_tenant = tenant_id or x_tenant_id
    if not resolved_tenant:
        raise HTTPException(status_code=400, detail="tenant_id or X-Tenant-Id required")
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
                else "Collection queued for operator fulfillment"
            )
        ),
    }


class IdpSyncRequest(BaseModel):
    provider: Literal["entra", "okta"] = "entra"
    payload: dict[str, Any] | list[Any] = Field(default_factory=dict)


class HrSyncRequest(BaseModel):
    format: Literal["csv", "json"] = "csv"
    csv_text: str | None = None
    payload: dict[str, Any] | None = None


class IdentityEvaluateRequest(BaseModel):
    idp_users: list[dict[str, Any]] = Field(default_factory=list)
    hr_employees: list[dict[str, Any]] = Field(default_factory=list)


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
def identity_evaluate(
    body: IdentityEvaluateRequest,
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    findings = evaluate_identity_checks(body.idp_users, body.hr_employees)
    return {"findings": findings, "count": len(findings)}


def run() -> None:
    import uvicorn

    uvicorn.run("integration_hub.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
