from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from code_processor.bindings import compliance_from_scanner_findings
from code_processor.cwe_normalize import (
    collect_cwe_ids,
    cwe_contributors,
    enrich_scanner_findings,
)
from code_processor.diff_parse import parse_unified_diff
from code_processor.extract import extract_changed_functions, extract_python_functions
from code_processor.scanners import scan_path_or_noop
from code_processor.workspace import materialize_patch_workspace

_VALID_SURFACES = {"network", "host", "webapp", "identity", "cloud", "code"}
_VALID_AUTOMATION = {"auto", "manual", "hybrid"}


def _split_env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def compliance_from_env() -> dict[str, Any] | None:
    """Build a compliance enrichment dict from environment configuration.

    Returns ``None`` unless ``PROFILE_PACK_IDS`` or ``COMPLIANCE_CHECK_IDS`` is
    set. The shape mirrors the finding ``compliance`` block:
    ``profile_pack_ids``, ``check_ids``, ``surfaces``, ``automation``.
    """
    pack_ids = _split_env_list("PROFILE_PACK_IDS")
    check_ids = _split_env_list("COMPLIANCE_CHECK_IDS")
    if not pack_ids and not check_ids:
        return None
    surfaces = [s for s in _split_env_list("PROFILE_SURFACES") if s in _VALID_SURFACES]
    if not surfaces:
        surfaces = ["code"]
    automation = os.environ.get("PROFILE_AUTOMATION", "auto").strip() or "auto"
    if automation not in _VALID_AUTOMATION:
        automation = "auto"
    return {
        "profile_pack_ids": pack_ids,
        "check_ids": check_ids,
        "surfaces": surfaces,
        "automation": automation,
    }


def process_code_change(payload: dict[str, Any]) -> dict[str, Any]:
    """Build a feature record plus advisory finding structure for one change."""
    diff_text = str(payload.get("diff") or payload.get("patch") or payload.get("diff_text") or "")
    files = parse_unified_diff(diff_text) if diff_text else []
    symbols = extract_changed_functions(diff_text) if diff_text else []

    source_blobs = payload.get("files") or {}
    if isinstance(source_blobs, dict):
        for path, source in source_blobs.items():
            if str(path).endswith(".py") and isinstance(source, str):
                for fn in extract_python_functions(source):
                    symbols.append(
                        {
                            "path": path,
                            "name": fn["name"],
                            "kind": "FunctionDef",
                            "lineno": fn["start_line"],
                            "end_lineno": fn["end_line"],
                            "body": fn["body"],
                        }
                    )

    with materialize_patch_workspace({"diff": diff_text, "files": source_blobs}) as tmpdir:
        scan = scan_path_or_noop(Path(tmpdir))

    scanner_findings = enrich_scanner_findings(list(scan["scanner_findings"] or []))
    cwe_ids = collect_cwe_ids(scanner_findings)
    contributors = cwe_contributors(scanner_findings)

    feature = {
        "schema_version": "1.0",
        "event_type": "code.features",
        "feature_version": "code.features.v1",
        "tenant_id": payload.get("tenant_id", "default"),
        "asset_id": payload.get("asset_id")
        or (payload.get("asset") or {}).get("asset_id", "repo"),
        "provider": payload.get("provider") or "unknown",
        "files_changed": [f["path"] for f in files]
        or list(source_blobs.keys() if isinstance(source_blobs, dict) else []),
        "diff_stats": {
            "files": len(files) or (len(source_blobs) if isinstance(source_blobs, dict) else 0),
            "added_lines": sum(len(f.get("added_lines") or []) for f in files),
            "removed_lines": sum(len(f.get("removed_lines") or []) for f in files),
        },
        "changed_symbols": symbols,
        "scanner_summary": scan["scanners"],
        "scanner_findings": scanner_findings,
        "cwe_ids": cwe_ids,
        "text_features": {
            "diff_text": diff_text[:8000],
            "has_auth_keywords": any(
                kw in diff_text.lower()
                for kw in ("password", "secret", "token", "auth", "permission")
            ),
            "has_network_keywords": any(
                kw in diff_text.lower() for kw in ("socket", "bind", "0.0.0.0", "eval(")
            ),
        },
    }

    finding = {
        "schema_version": "1.0",
        "event_type": "code.findings",
        "finding_type": "code_advisory",
        "tenant_id": feature["tenant_id"],
        "asset_id": feature["asset_id"],
        "advisory_only": True,
        "scanner_findings": scanner_findings,
        "scanners": scan["scanners"],
        "cwe_ids": cwe_ids,
        "contributors": contributors,
        "prep_for_model": True,
        "feature_ref": {
            "files_changed": feature["files_changed"],
            "diff_stats": feature["diff_stats"],
        },
    }

    compliance = _merge_compliance(
        compliance_from_scanner_findings(scanner_findings),
        compliance_from_env(),
    )
    if compliance is not None:
        finding["compliance"] = compliance
        feature["compliance"] = compliance

    return {"feature": feature, "finding": finding}


def _merge_compliance(
    from_findings: dict[str, Any] | None,
    from_env: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Union pack/check ids from scanner map hits and explicit env config."""
    if from_findings is None and from_env is None:
        return None
    packs: list[str] = []
    checks: list[str] = []
    surfaces: list[str] = []
    automation = "auto"
    for block in (from_findings, from_env):
        if not block:
            continue
        for pid in block.get("profile_pack_ids") or []:
            if pid not in packs:
                packs.append(str(pid))
        for cid in block.get("check_ids") or []:
            if cid not in checks:
                checks.append(str(cid))
        for surface in block.get("surfaces") or []:
            if surface in _VALID_SURFACES and surface not in surfaces:
                surfaces.append(surface)
        auto = block.get("automation")
        if auto in _VALID_AUTOMATION:
            automation = str(auto)
    if not packs and not checks:
        return None
    return {
        "profile_pack_ids": packs,
        "check_ids": checks,
        "surfaces": surfaces or ["code"],
        "automation": automation,
    }


class CodePipeline:
    def __init__(self) -> None:
        self.processed = 0
        self.published = 0
        self.errors = 0

    def process_events(
        self, events: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        features: list[dict[str, Any]] = []
        findings_out: list[dict[str, Any]] = []
        for event in events:
            try:
                feat, finding = self.process_one(event)
                features.append(feat)
                findings_out.append(finding)
                self.processed += 1
                self.published += 1
            except Exception:
                self.errors += 1
        return features, findings_out

    def process_one(self, event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        ext = event.get("extensions") or {}
        payload = event.get("payload") or ext.get("raw_payload") or ext
        if isinstance(payload, str):
            body: dict[str, Any] = {"diff": payload}
        elif isinstance(payload, dict):
            body = dict(payload)
        else:
            body = {}
        body.setdefault("tenant_id", event.get("tenant_id", "default"))
        if "asset_id" not in body:
            body["asset_id"] = (event.get("asset") or {}).get("asset_id", "repo")
        if "provider" not in body:
            body["provider"] = ext.get("provider") or body.get("provider") or "unknown"

        result = process_code_change(body)
        return result["feature"], result["finding"]
