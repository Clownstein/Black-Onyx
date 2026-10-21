"""Map Antares SARIF / JSON report output to evidence_refs and contributors.

# MITRE CWE notice
# Evidence may reference Common Weakness Enumeration (CWE) identifiers from
# The MITRE Corporation (https://cwe.mitre.org/). See CWE Terms of Use.
"""

from __future__ import annotations

from typing import Any


def extract_cwe_ids_from_plan(plan_data: Any) -> list[str]:
    """Pull selected CWE IDs from ``antares plan --json`` output."""
    if not isinstance(plan_data, dict):
        return []
    candidates: list[Any] = []
    for key in ("cwe_ids", "selected_cwes", "selected_cwe_ids"):
        val = plan_data.get(key)
        if isinstance(val, list):
            candidates.extend(val)
    selection = plan_data.get("selection") or plan_data.get("cwes") or {}
    if isinstance(selection, dict):
        for key in ("cwe_ids", "ids", "selected"):
            val = selection.get(key)
            if isinstance(val, list):
                candidates.extend(val)
    elif isinstance(selection, list):
        candidates.extend(selection)

    out: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        cwe = _as_cwe(item)
        if cwe and cwe not in seen:
            seen.add(cwe)
            out.append(cwe)
    return out


def map_antares_result(data: Any) -> dict[str, Any]:
    """Normalize Antares tool/plan JSON (or SARIF) into evidence + contributors."""
    evidence_refs: list[str] = []
    contributors: list[dict[str, Any]] = []
    file_hits: list[dict[str, Any]] = []
    cwe_ids: list[str] = []

    if isinstance(data, dict) and data.get("runs") and data.get("version"):
        # SARIF-ish
        return _map_sarif(data)

    findings = []
    if isinstance(data, dict):
        findings = data.get("findings") or data.get("results") or []
        if not findings and isinstance(data.get("report"), dict):
            findings = data["report"].get("findings") or []
        cwe_ids = extract_cwe_ids_from_plan(data)
        summary = data.get("summary") or data.get("report_summary") or {}
        if isinstance(summary, dict):
            for c in summary.get("cwe_ids_triggered") or []:
                cwe = _as_cwe(c)
                if cwe and cwe not in cwe_ids:
                    cwe_ids.append(cwe)

    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                continue
            path = str(item.get("file_path") or item.get("path") or item.get("uri") or "")
            item_cwes = [
                c for c in (_as_cwe(x) for x in (item.get("cwe_ids") or [item.get("cwe_id")]))
                if c
            ]
            for c in item_cwes:
                if c not in cwe_ids:
                    cwe_ids.append(c)
            title = str(item.get("title") or item.get("message") or "antares-finding")
            ref = f"antares:{path}:{','.join(item_cwes) or 'unknown'}"
            if ref not in evidence_refs:
                evidence_refs.append(ref)
            hit = {"path": path, "cwe_ids": item_cwes, "title": title}
            file_hits.append(hit)
            contributors.append(
                {
                    "type": "antares_localization",
                    "path": path,
                    "cwe_ids": item_cwes,
                    "title": title,
                    "contribution": float(item.get("confidence") or 0.5),
                    "human_review_required": True,
                }
            )

    if not evidence_refs and cwe_ids:
        evidence_refs = [f"antares:cwe:{c}" for c in cwe_ids]

    return {
        "evidence_refs": evidence_refs,
        "contributors": contributors,
        "file_hits": file_hits,
        "cwe_ids": cwe_ids,
    }


def _map_sarif(sarif: dict[str, Any]) -> dict[str, Any]:
    evidence_refs: list[str] = []
    contributors: list[dict[str, Any]] = []
    file_hits: list[dict[str, Any]] = []
    cwe_ids: list[str] = []

    for run in sarif.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "")
            cwe = _as_cwe(rule_id) or _as_cwe(
                ((result.get("properties") or {}) if isinstance(result.get("properties"), dict) else {}).get(
                    "cwe"
                )
            )
            locs = result.get("locations") or []
            path = ""
            if locs and isinstance(locs[0], dict):
                phys = (locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}
                path = str(phys.get("uri") or "")
            item_cwes = [cwe] if cwe else []
            for c in item_cwes:
                if c not in cwe_ids:
                    cwe_ids.append(c)
            title = str(((result.get("message") or {}) if isinstance(result.get("message"), dict) else {}).get("text") or rule_id or "sarif")
            ref = f"sarif:{path}:{cwe or rule_id or 'unknown'}"
            if ref not in evidence_refs:
                evidence_refs.append(ref)
            file_hits.append({"path": path, "cwe_ids": item_cwes, "title": title})
            contributors.append(
                {
                    "type": "antares_sarif",
                    "path": path,
                    "cwe_ids": item_cwes,
                    "title": title,
                    "contribution": 0.5,
                    "human_review_required": True,
                }
            )

    return {
        "evidence_refs": evidence_refs,
        "contributors": contributors,
        "file_hits": file_hits,
        "cwe_ids": cwe_ids,
    }


def _as_cwe(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("id") or value.get("cwe_id") or value.get("cwe")
    text = str(value).strip()
    if not text:
        return None
    upper = text.upper().replace("_", "-").replace(" ", "")
    if upper.startswith("CWE-"):
        digits = "".join(ch for ch in upper[4:] if ch.isdigit())
        if digits:
            return f"CWE-{int(digits)}"
    if text.isdigit():
        return f"CWE-{int(text)}"
    # ruleId like CWE89
    if upper.startswith("CWE") and upper[3:].isdigit():
        return f"CWE-{int(upper[3:])}"
    return None
