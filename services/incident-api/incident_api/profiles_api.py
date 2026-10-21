"""Security packs + tenant security profile CRUD / coverage / evaluate."""

from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from ulid import ULID

from incident_api.db import get_db
from incident_api.models import (
    FindingRow,
    ProfileAttestationRow,
    ProfileCheckStateRow,
    ProfileExceptionRow,
    SecurityProfileRow,
)
from incident_api.profiles.pack_loader import load_all_packs, load_presets, merge_packs
from incident_api.schemas import (
    CertificationPackageRequest,
    ProfileAttestRequest,
    ProfileExceptionCreate,
    SecurityProfileCreate,
    SecurityProfilePatch,
    SecurityProfileRead,
)
from incident_api.tenant import Principal, require_principal, require_role

router = APIRouter(tags=["security-profiles"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_read(row: SecurityProfileRow, *, include_preview: bool = False) -> SecurityProfileRead:
    preview = None
    if include_preview:
        resolved = merge_packs(list(row.selected_packs or []), enabled_surfaces=list(row.enabled_surfaces or []) or None)
        preview = resolved.to_dict()
    return SecurityProfileRead(
        profile_id=row.profile_id,
        tenant_id=row.tenant_id,
        name=row.name,
        selected_packs=list(row.selected_packs or []),
        asset_scope=list(row.asset_scope or []),
        enabled_surfaces=list(row.enabled_surfaces or []),
        schedule=row.schedule,
        strictness=row.strictness,
        merge_policy=row.merge_policy,
        active=bool(row.active),
        preview=preview,
    )


def _get_profile(db: Session, tenant_id: str, profile_id: str) -> SecurityProfileRow:
    row = db.scalar(
        select(SecurityProfileRow).where(
            SecurityProfileRow.tenant_id == tenant_id,
            SecurityProfileRow.profile_id == profile_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="security profile not found")
    return row


@router.get("/api/v1/security-packs")
def list_packs(
    kind: str | None = Query(default=None),
    _principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    packs = load_all_packs()
    items = [p.to_dict() for p in packs.values() if kind is None or p.kind == kind]
    items.sort(key=lambda x: x["pack_id"])
    return {"items": items, "presets": load_presets()}


@router.get("/api/v1/security-packs/{pack_id}")
def get_pack(
    pack_id: str,
    _principal: Principal = Depends(require_principal),
) -> dict[str, Any]:
    packs = load_all_packs()
    pack = packs.get(pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="pack not found")
    return pack.to_dict()


@router.get("/api/v1/security-profiles")
def list_profiles(
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = db.scalars(
        select(SecurityProfileRow).where(SecurityProfileRow.tenant_id == principal.tenant_id)
    ).all()
    return {"items": [_row_to_read(r) for r in rows]}


@router.post("/api/v1/security-profiles", response_model=SecurityProfileRead)
def create_profile(
    body: SecurityProfileCreate,
    principal: Principal = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> SecurityProfileRead:
    profile_id = body.profile_id or f"spf-{ULID()}"
    existing = db.scalar(
        select(SecurityProfileRow).where(
            SecurityProfileRow.tenant_id == principal.tenant_id,
            SecurityProfileRow.profile_id == profile_id,
        )
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="profile_id already exists")
    unknown = [p for p in body.selected_packs if p not in load_all_packs()]
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown packs: {unknown}")
    row = SecurityProfileRow(
        profile_id=profile_id,
        tenant_id=principal.tenant_id,
        name=body.name,
        selected_packs=list(body.selected_packs),
        asset_scope=list(body.asset_scope),
        enabled_surfaces=list(body.enabled_surfaces),
        schedule=body.schedule,
        strictness=body.strictness,
        merge_policy=body.merge_policy or "union_strictest",
        active=body.active,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _row_to_read(row, include_preview=True)


@router.get("/api/v1/security-profiles/{profile_id}", response_model=SecurityProfileRead)
def get_profile(
    profile_id: str,
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
) -> SecurityProfileRead:
    row = _get_profile(db, principal.tenant_id, profile_id)
    return _row_to_read(row, include_preview=True)


@router.patch("/api/v1/security-profiles/{profile_id}", response_model=SecurityProfileRead)
def patch_profile(
    profile_id: str,
    body: SecurityProfilePatch,
    principal: Principal = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> SecurityProfileRead:
    row = _get_profile(db, principal.tenant_id, profile_id)
    data = body.model_dump(exclude_unset=True)
    if "selected_packs" in data:
        unknown = [p for p in data["selected_packs"] if p not in load_all_packs()]
        if unknown:
            raise HTTPException(status_code=400, detail=f"unknown packs: {unknown}")
    for key, val in data.items():
        setattr(row, key, val)
    db.commit()
    db.refresh(row)
    return _row_to_read(row, include_preview=True)


@router.delete("/api/v1/security-profiles/{profile_id}")
def delete_profile(
    profile_id: str,
    principal: Principal = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    row = _get_profile(db, principal.tenant_id, profile_id)
    db.delete(row)
    db.commit()
    return {"status": "deleted"}


def _evaluate_profile(
    db: Session,
    tenant_id: str,
    row: SecurityProfileRow,
    *,
    persist: bool = True,
) -> dict[str, Any]:
    resolved = merge_packs(
        list(row.selected_packs or []),
        enabled_surfaces=list(row.enabled_surfaces or []) or None,
    )
    findings = db.scalars(
        select(FindingRow).where(FindingRow.tenant_id == tenant_id)
    ).all()
    finding_check_hits: dict[str, list[str]] = {}
    finding_pass_hits: dict[str, list[str]] = {}
    for f in findings:
        payload = f.payload or {}
        compliance = payload.get("compliance") or (payload.get("context") or {}).get("compliance") or {}
        check_ids = [str(cid) for cid in (compliance.get("check_ids") or [])]
        finding_type = str(payload.get("finding_type") or f.finding_type or "")
        is_pass_evidence = finding_type in {"probe_ok", "compliance_ok", "telemetry_ok"}
        for cid in check_ids:
            if is_pass_evidence:
                finding_pass_hits.setdefault(cid, []).append(f.finding_id)
            else:
                finding_check_hits.setdefault(cid, []).append(f.finding_id)

    attestations = {
        a.check_id: a
        for a in db.scalars(
            select(ProfileAttestationRow).where(
                ProfileAttestationRow.tenant_id == tenant_id,
                ProfileAttestationRow.profile_id == row.profile_id,
            )
        ).all()
    }
    exceptions = {
        e.check_id: e
        for e in db.scalars(
            select(ProfileExceptionRow).where(
                ProfileExceptionRow.tenant_id == tenant_id,
                ProfileExceptionRow.profile_id == row.profile_id,
                ProfileExceptionRow.status == "open",
            )
        ).all()
    }

    coverage: list[dict[str, Any]] = []
    now = _now()
    for chk in resolved.checks:
        status = "unknown"
        reason = "telemetry_missing"
        linked: list[str] = []
        if chk.check_id in exceptions:
            status = "not_applicable"
            reason = "exception"
        elif chk.check_id in attestations and chk.automation in ("manual", "hybrid"):
            status = "attested"
            reason = None
        elif chk.check_id in finding_check_hits:
            status = "fail"
            reason = "open_finding"
            linked = finding_check_hits[chk.check_id]
        elif chk.check_id in finding_pass_hits:
            status = "pass"
            reason = "telemetry_ok"
            linked = finding_pass_hits[chk.check_id]
        elif chk.automation == "manual":
            status = "unknown"
            reason = "awaiting_attestation"
        elif chk.automation in ("auto", "hybrid"):
            # Never silent-pass: missing telemetry stays unknown until a probe /
            # evaluator / attestation provides positive evidence of pass.
            status = "unknown"
            reason = "telemetry_missing"

        if persist:
            existing = db.scalar(
                select(ProfileCheckStateRow).where(
                    ProfileCheckStateRow.tenant_id == tenant_id,
                    ProfileCheckStateRow.profile_id == row.profile_id,
                    ProfileCheckStateRow.check_id == chk.check_id,
                )
            )
            if existing is None:
                existing = ProfileCheckStateRow(
                    tenant_id=tenant_id,
                    profile_id=row.profile_id,
                    check_id=chk.check_id,
                )
                db.add(existing)
            existing.status = status
            existing.reason = reason
            existing.finding_ids = linked
            existing.detail = {"title": chk.title, "pack_ids": chk.pack_ids}
            existing.evaluated_at = now
        coverage.append(
            {
                "check_id": chk.check_id,
                "title": chk.title,
                "status": status,
                "reason": reason,
                "finding_ids": linked,
                "automation": chk.automation,
                "surfaces": chk.surfaces,
                "pack_ids": chk.pack_ids,
                "severity_default": chk.severity_default,
            }
        )
    if persist:
        db.commit()
    summary = {
        "pass": sum(1 for c in coverage if c["status"] == "pass"),
        "fail": sum(1 for c in coverage if c["status"] == "fail"),
        "unknown": sum(1 for c in coverage if c["status"] == "unknown"),
        "attested": sum(1 for c in coverage if c["status"] == "attested"),
        "not_applicable": sum(1 for c in coverage if c["status"] == "not_applicable"),
    }
    return {
        "profile_id": row.profile_id,
        "resolved": resolved.to_dict(),
        "coverage": coverage,
        "summary": summary,
        "evaluated_at": now.isoformat(),
    }


@router.post("/api/v1/security-profiles/{profile_id}/evaluate")
def evaluate_profile(
    profile_id: str,
    principal: Principal = Depends(require_role("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = _get_profile(db, principal.tenant_id, profile_id)
    return _evaluate_profile(db, principal.tenant_id, row)


@router.get("/api/v1/security-profiles/{profile_id}/coverage")
def coverage(
    profile_id: str,
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = _get_profile(db, principal.tenant_id, profile_id)
    states = db.scalars(
        select(ProfileCheckStateRow).where(
            ProfileCheckStateRow.tenant_id == principal.tenant_id,
            ProfileCheckStateRow.profile_id == profile_id,
        )
    ).all()
    if not states:
        return _evaluate_profile(db, principal.tenant_id, row)
    resolved = merge_packs(
        list(row.selected_packs or []),
        enabled_surfaces=list(row.enabled_surfaces or []) or None,
    )
    by_id = {c.check_id: c for c in resolved.checks}
    coverage_items = []
    for s in states:
        chk = by_id.get(s.check_id)
        detail = s.detail or {}
        coverage_items.append(
            {
                "check_id": s.check_id,
                "title": (chk.title if chk else None) or detail.get("title") or s.check_id,
                "status": s.status,
                "reason": s.reason,
                "finding_ids": list(s.finding_ids or []),
                "automation": chk.automation if chk else "unknown",
                "surfaces": list(chk.surfaces) if chk else [],
                "detail": detail,
                "evaluated_at": s.evaluated_at.isoformat() if s.evaluated_at else None,
            }
        )
    summary = {
        "pass": sum(1 for c in coverage_items if c["status"] == "pass"),
        "fail": sum(1 for c in coverage_items if c["status"] == "fail"),
        "unknown": sum(1 for c in coverage_items if c["status"] == "unknown"),
        "attested": sum(1 for c in coverage_items if c["status"] == "attested"),
        "not_applicable": sum(1 for c in coverage_items if c["status"] == "not_applicable"),
    }
    return {"profile_id": profile_id, "coverage": coverage_items, "summary": summary}


@router.get("/api/v1/security-profiles/{profile_id}/export")
def export_profile(
    profile_id: str,
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = _get_profile(db, principal.tenant_id, profile_id)
    result = _evaluate_profile(db, principal.tenant_id, row)
    result["export_format"] = "json"
    result["name"] = row.name
    result["selected_packs"] = list(row.selected_packs or [])
    return result


@router.post("/api/v1/security-profiles/{profile_id}/attest")
def attest_check(
    profile_id: str,
    body: ProfileAttestRequest,
    principal: Principal = Depends(require_role("analyst")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _get_profile(db, principal.tenant_id, profile_id)
    att = ProfileAttestationRow(
        attestation_id=f"att-{ULID()}",
        tenant_id=principal.tenant_id,
        profile_id=profile_id,
        check_id=body.check_id,
        author=principal.subject,
        note=body.note,
        evidence_links=list(body.evidence_links),
    )
    db.add(att)
    state = db.scalar(
        select(ProfileCheckStateRow).where(
            ProfileCheckStateRow.tenant_id == principal.tenant_id,
            ProfileCheckStateRow.profile_id == profile_id,
            ProfileCheckStateRow.check_id == body.check_id,
        )
    )
    if state is None:
        state = ProfileCheckStateRow(
            tenant_id=principal.tenant_id,
            profile_id=profile_id,
            check_id=body.check_id,
        )
        db.add(state)
    state.status = "attested"
    state.reason = None
    state.evaluated_at = _now()
    db.commit()
    return {"attestation_id": att.attestation_id, "status": "attested"}


@router.post("/api/v1/security-profiles/{profile_id}/exceptions")
def create_exception(
    profile_id: str,
    body: ProfileExceptionCreate,
    principal: Principal = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _get_profile(db, principal.tenant_id, profile_id)
    exc = ProfileExceptionRow(
        exception_id=f"exc-{ULID()}",
        tenant_id=principal.tenant_id,
        profile_id=profile_id,
        check_id=body.check_id,
        rationale=body.rationale,
        owner=body.owner,
        expires_at=body.expires_at,
        status="open",
    )
    db.add(exc)
    db.commit()
    return {"exception_id": exc.exception_id, "status": "open"}


@router.get("/api/v1/security-profiles/{profile_id}/exceptions")
def list_exceptions(
    profile_id: str,
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _get_profile(db, principal.tenant_id, profile_id)
    rows = db.scalars(
        select(ProfileExceptionRow).where(
            ProfileExceptionRow.tenant_id == principal.tenant_id,
            ProfileExceptionRow.profile_id == profile_id,
        )
    ).all()
    return {
        "items": [
            {
                "exception_id": e.exception_id,
                "check_id": e.check_id,
                "rationale": e.rationale,
                "owner": e.owner,
                "status": e.status,
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
            }
            for e in rows
        ]
    }


def _certification_package_body(
    db: Session,
    principal: Principal,
    profile_id: str,
    body: CertificationPackageRequest,
) -> dict[str, Any]:
    """Milestone H: auditor-ready evidence package (not a certificate).

    Read-only: evaluation is computed without persisting check-state so an
    auditor (viewer) export has no side effects.
    """
    row = _get_profile(db, principal.tenant_id, profile_id)
    evaluated = _evaluate_profile(db, principal.tenant_id, row, persist=False)
    crosswalk = {
        "soc2": ["soc2-security", "soc2-tsc", "cis-v8-ig1"],
        "pci_dss_4": ["pci-dss-4", "pci-dss-4-cert", "pci-merchant"],
        "cmmc_l2": ["cmmc-l2", "cmmc-l2-cert", "nist-800-53-mod"],
        "fedramp_mod": ["fedramp-mod", "fedramp-mod-cert", "nist-800-53-mod"],
    }
    target = body.target.lower()
    if target not in crosswalk:
        raise HTTPException(status_code=400, detail=f"unsupported target {body.target}")
    cert_resolved = merge_packs(crosswalk[target])
    coverage = list(evaluated["coverage"])
    # Never silently omit fail/unknown rows from the package matrix.
    fail_rows = [c for c in coverage if c["status"] == "fail"]
    unknown_rows = [c for c in coverage if c["status"] == "unknown"]
    if not body.include_unknown:
        coverage_export = [c for c in coverage if c["status"] != "unknown"]
    else:
        coverage_export = coverage
    control_matrix = [
        {
            "control_id": c.check_id,
            "title": c.title,
            "status": next(
                (row["status"] for row in coverage if row["check_id"] == c.check_id),
                "unknown",
            ),
            "pack_ids": c.pack_ids,
        }
        for c in cert_resolved.checks
    ]
    exceptions = [
        {
            "exception_id": e.exception_id,
            "check_id": e.check_id,
            "rationale": e.rationale,
            "owner": e.owner,
            "status": e.status,
        }
        for e in db.scalars(
            select(ProfileExceptionRow).where(
                ProfileExceptionRow.tenant_id == principal.tenant_id,
                ProfileExceptionRow.profile_id == profile_id,
            )
        ).all()
    ]
    package_id = f"cert-{profile_id}-{target}-{_now().strftime('%Y%m%d%H%M%S')}"
    return {
        "package_id": package_id,
        "disclaimer": (
            "This package is evidence assistance for external assessors. "
            "It is not a SOC 2, PCI ROC, CMMC, or FedRAMP authorization."
        ),
        "target": target,
        "profile_id": profile_id,
        "name": row.name,
        "selected_packs": list(row.selected_packs or []),
        "recommended_packs": crosswalk[target],
        "summary": evaluated["summary"],
        "coverage": coverage_export,
        "fail_rows": fail_rows,
        "unknown_rows": unknown_rows,
        "control_matrix": control_matrix,
        "control_count": len(control_matrix),
        "exceptions": exceptions,
        "generated_at": _now().isoformat(),
    }


def _control_matrix_csv(package: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=["control_id", "title", "status", "pack_ids"]
    )
    writer.writeheader()
    for row in package.get("control_matrix") or []:
        writer.writerow(
            {
                "control_id": row.get("control_id"),
                "title": row.get("title"),
                "status": row.get("status"),
                "pack_ids": ",".join(row.get("pack_ids") or []),
            }
        )
    return buf.getvalue()


@router.post("/api/v1/security-profiles/{profile_id}/certification-package")
def certification_package(
    profile_id: str,
    body: CertificationPackageRequest,
    export_format: str = Query(default="json"),
    principal: Principal = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
) -> Any:
    package = _certification_package_body(db, principal, profile_id, body)
    fmt = (export_format or "json").lower()
    if fmt not in {"json", "csv", "zip"}:
        raise HTTPException(status_code=400, detail="export_format must be json|csv|zip")
    if fmt == "json":
        return package
    csv_text = _control_matrix_csv(package)
    if fmt == "csv":
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{package["package_id"]}-matrix.csv"'
                )
            },
        )
    # zip: JSON package + control matrix CSV + cover sheet markdown
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{package['package_id']}.json", json.dumps(package, indent=2))
        zf.writestr(f"{package['package_id']}-matrix.csv", csv_text)
        cover = (
            f"# Certification evidence package\n\n"
            f"**Disclaimer:** {package['disclaimer']}\n\n"
            f"- package_id: `{package['package_id']}`\n"
            f"- target: `{package['target']}`\n"
            f"- profile: `{package['profile_id']}` ({package['name']})\n"
            f"- generated_at: `{package['generated_at']}`\n"
            f"- fail_rows: {len(package['fail_rows'])}\n"
            f"- unknown_rows: {len(package['unknown_rows'])}\n"
        )
        zf.writestr("README.md", cover)
    mem.seek(0)
    return StreamingResponse(
        mem,
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{package["package_id"]}.zip"'
            )
        },
    )

