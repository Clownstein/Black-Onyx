"""Enrichment orchestration: snapshot → plan/CWE → optional Antares tool → incident-api."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from code_enrichment_worker import antares_cli
from code_enrichment_worker.config import settings
from code_enrichment_worker.incident_client import post_enrichment_finding
from code_enrichment_worker.sarif_map import extract_cwe_ids_from_plan, map_antares_result
from code_enrichment_worker.snapshot import snapshot_repo

logger = logging.getLogger(__name__)


def _collect_request_cwes(request: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for key in ("cwe_ids", "cwes"):
        val = request.get(key)
        if isinstance(val, list):
            for item in val:
                text = str(item).strip().upper().replace("_", "-")
                if text.startswith("CWE"):
                    digits = "".join(ch for ch in text[3:] if ch.isdigit())
                    if digits:
                        cwes.append(f"CWE-{int(digits)}")
    finding = request.get("finding") if isinstance(request.get("finding"), dict) else {}
    for item in finding.get("cwe_ids") or finding.get("contributors") or []:
        if isinstance(item, str):
            text = item.upper().replace("_", "-")
            if text.startswith("CWE"):
                digits = "".join(ch for ch in text[3:] if ch.isdigit())
                if digits:
                    cwes.append(f"CWE-{int(digits)}")
        elif isinstance(item, dict) and item.get("cwe_id"):
            cwes.append(str(item["cwe_id"]))
    for sf in finding.get("scanner_findings") or request.get("scanner_findings") or []:
        if isinstance(sf, dict) and sf.get("cwe_id"):
            cwes.append(str(sf["cwe_id"]))
    # Dedupe preserve order
    out: list[str] = []
    seen: set[str] = set()
    for c in cwes:
        c2 = c if c.startswith("CWE-") else f"CWE-{c}" if c.isdigit() else c
        if c2 not in seen:
            seen.add(c2)
            out.append(c2)
    return out


def enrich_code(request: dict[str, Any]) -> dict[str, Any]:
    """Run enrichment for one request. Never performs autonomous remediation."""
    tenant_id = str(request.get("tenant_id") or "default")
    finding = request.get("finding") if isinstance(request.get("finding"), dict) else {}
    finding_id = request.get("finding_id") or finding.get("finding_id")
    asset_id = str(
        request.get("asset_id")
        or finding.get("asset_id")
        or (request.get("asset") or {}).get("asset_id")
        or "repo"
    )
    service_id = request.get("service_id") or finding.get("service_id")
    cwe_ids = _collect_request_cwes(request)
    model_ran = False
    degraded = False
    plan_result: dict[str, Any] | None = None
    tool_result: dict[str, Any] | None = None
    mapped: dict[str, Any] = {
        "evidence_refs": [],
        "contributors": [],
        "file_hits": [],
        "cwe_ids": list(cwe_ids),
    }

    with snapshot_repo(request) as root:
        target = str(root)

        if not cwe_ids:
            plan_result = antares_cli.run_plan(target)
            planned = extract_cwe_ids_from_plan(plan_result.get("data"))
            if planned:
                cwe_ids = planned
            elif plan_result.get("ok") is False:
                degraded = True
                logger.info("antares plan failed or unavailable: %s", plan_result.get("error"))

        endpoint = (settings.antares_endpoint or "").strip()
        if endpoint and cwe_ids:
            tool_result = antares_cli.run_tool_query(target, cwe_ids)
            model_ran = True
            if tool_result.get("data"):
                mapped = map_antares_result(tool_result["data"])
            if not tool_result.get("ok"):
                degraded = True
        elif endpoint and not cwe_ids:
            tool_result = antares_cli.run_tool_sweep(target)
            model_ran = True
            if tool_result.get("data"):
                mapped = map_antares_result(tool_result["data"])
            if not tool_result.get("ok"):
                degraded = True
        else:
            # No model endpoint: plan/CWE-only path is complete and OK (degraded).
            degraded = True
            if plan_result and plan_result.get("data"):
                mapped = map_antares_result(plan_result["data"])
            mapped["cwe_ids"] = list(dict.fromkeys([*(mapped.get("cwe_ids") or []), *cwe_ids]))
            if cwe_ids and not mapped.get("evidence_refs"):
                mapped["evidence_refs"] = [f"antares:cwe:{c}" for c in cwe_ids]
                mapped["contributors"] = [
                    {
                        "type": "cwe_plan",
                        "cwe_id": c,
                        "contribution": 0.4,
                        "human_review_required": True,
                    }
                    for c in cwe_ids
                ]

    final_cwes = list(dict.fromkeys([*(mapped.get("cwe_ids") or []), *cwe_ids]))
    status = "completed_degraded" if degraded and not model_ran else (
        "completed_degraded" if degraded else "completed"
    )
    if model_ran and not degraded:
        status = "completed"

    enrichment_meta = {
        "status": status,
        "model_ran": model_ran,
        "degraded": degraded,
        "antares_endpoint_set": bool((settings.antares_endpoint or "").strip()),
        "cwe_ids": final_cwes,
        "file_hits": mapped.get("file_hits") or [],
        "human_review_required": True,
        "autonomous_remediation": False,
        "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "plan_ok": None if plan_result is None else bool(plan_result.get("ok")),
        "tool_ok": None if tool_result is None else bool(tool_result.get("ok")),
        "advisory": (
            "Antares results are file-level leads for human review only. "
            "No autonomous remediation is performed."
        ),
    }

    persist = post_enrichment_finding(
        tenant_id=tenant_id,
        finding_id=str(finding_id) if finding_id else None,
        asset_id=asset_id,
        service_id=str(service_id) if service_id else None,
        evidence_refs=list(mapped.get("evidence_refs") or []),
        contributors=list(mapped.get("contributors") or []),
        cwe_ids=final_cwes,
        enrichment=enrichment_meta,
        calibrated_score=float(
            request.get("calibrated_score")
            or finding.get("calibrated_score")
            or 0.5
        ),
        severity_hint=request.get("severity_hint") or finding.get("severity_hint") or "medium",
    )

    return {
        "status": status,
        "finding_id": persist.get("finding_id") or finding_id,
        "cwe_ids": final_cwes,
        "evidence_refs": mapped.get("evidence_refs") or [],
        "contributors": mapped.get("contributors") or [],
        "file_hits": mapped.get("file_hits") or [],
        "enrichment": enrichment_meta,
        "persist": persist,
        "human_review_required": True,
        "autonomous_remediation": False,
    }
