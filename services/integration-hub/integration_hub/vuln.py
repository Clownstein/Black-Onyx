"""Normalize Trivy / Grype-like vulnerability scan JSON into platform findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from black_onyx_contracts import Finding, FindingContributor, FindingWindow
from ulid import ULID

FEATURE_VERSION = "vuln.ingest.v1"
MODEL_NAME = "vuln-ingest"
MODEL_VERSION = "1.0.0"

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "negligible": "low",
    "unknown": "medium",
    "info": "low",
}


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return _now()
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return _now()


def _severity(raw: Any) -> str:
    key = str(raw or "unknown").strip().lower()
    return _SEVERITY_MAP.get(key, "medium")


def _score_for_severity(severity: str) -> float:
    return {
        "critical": 0.95,
        "high": 0.8,
        "medium": 0.55,
        "low": 0.3,
    }.get(severity, 0.5)


def _extract_cve(item: dict[str, Any]) -> str | None:
    for key in ("VulnerabilityID", "vulnerabilityID", "cve", "CVE", "id", "Id"):
        value = item.get(key)
        if isinstance(value, str) and value.upper().startswith("CVE-"):
            return value.upper()
    vuln = item.get("vulnerability") if isinstance(item.get("vulnerability"), dict) else {}
    for key in ("id", "cve", "VulnerabilityID"):
        value = vuln.get(key)
        if isinstance(value, str) and value.upper().startswith("CVE-"):
            return value.upper()
    related = item.get("relatedVulnerabilities") or item.get("related") or []
    if isinstance(related, list):
        for entry in related:
            if isinstance(entry, str) and entry.upper().startswith("CVE-"):
                return entry.upper()
            if isinstance(entry, dict):
                rid = entry.get("id") or entry.get("VulnerabilityID")
                if isinstance(rid, str) and rid.upper().startswith("CVE-"):
                    return rid.upper()
    return None


def _iter_trivy_vulns(payload: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for result in payload.get("Results") or payload.get("results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target") or result.get("target")
        for vuln in result.get("Vulnerabilities") or result.get("vulnerabilities") or []:
            if isinstance(vuln, dict):
                row = dict(vuln)
                row["_target"] = target
                row["_scanner"] = "trivy"
                results.append(row)
    return results


def _iter_grype_vulns(payload: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    matches = payload.get("matches") or payload.get("Matches") or []
    for match in matches:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability") if isinstance(match.get("vulnerability"), dict) else {}
        artifact = match.get("artifact") if isinstance(match.get("artifact"), dict) else {}
        row = {
            **vuln,
            "Severity": vuln.get("severity") or vuln.get("Severity"),
            "PkgName": artifact.get("name"),
            "InstalledVersion": artifact.get("version"),
            "Title": vuln.get("description") or vuln.get("id"),
            "_target": artifact.get("name"),
            "_scanner": "grype",
            "relatedVulnerabilities": match.get("relatedVulnerabilities") or [],
        }
        results.append(row)
    return results


def extract_vulnerabilities(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Accept Trivy, Grype, or a flat ``vulnerabilities`` list."""
    if payload.get("Results") or payload.get("results"):
        return _iter_trivy_vulns(payload)
    if payload.get("matches") or payload.get("Matches"):
        return _iter_grype_vulns(payload)
    flat = payload.get("vulnerabilities") or payload.get("Vulnerabilities") or []
    rows: list[dict[str, Any]] = []
    if isinstance(flat, list):
        for item in flat:
            if isinstance(item, dict):
                row = dict(item)
                row.setdefault("_scanner", "generic")
                rows.append(row)
    return rows


def vulnerability_to_finding(
    item: dict[str, Any],
    *,
    tenant_id: str,
    asset_id: str,
    kev_boost: bool = False,
    kev_boost_amount: float = 0.25,
    threat_intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cve = _extract_cve(item) or str(item.get("VulnerabilityID") or item.get("id") or "UNKNOWN")
    severity = _severity(item.get("Severity") or item.get("severity"))
    score = _score_for_severity(severity)
    if kev_boost:
        score = min(1.0, score + kev_boost_amount)
        if severity in {"low", "medium"}:
            severity = "high"
        elif severity == "high":
            severity = "critical"
    occurred = _parse_ts(item.get("PublishedDate") or item.get("published") or item.get("occurred_at"))
    pkg = item.get("PkgName") or item.get("package") or item.get("PkgID")
    version = item.get("InstalledVersion") or item.get("installed_version")
    title = item.get("Title") or item.get("title") or cve
    finding = Finding(
        finding_id=str(ULID()),
        tenant_id=tenant_id,
        finding_type="vulnerability",
        asset_id=asset_id,
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        feature_version=FEATURE_VERSION,
        raw_score=score,
        calibrated_score=score,
        severity_hint=severity,  # type: ignore[arg-type]
        window=FindingWindow(start=occurred, end=occurred),
        contributors=[
            FindingContributor(
                type="vuln_ingest",
                contribution=score,
                summary=f"{cve} on {asset_id}",
            )
        ],
        evidence_refs=[],
        context={
            "cve": cve,
            "package": pkg,
            "installed_version": version,
            "fixed_version": item.get("FixedVersion") or item.get("fix"),
            "title": title,
            "target": item.get("_target"),
            "scanner": item.get("_scanner") or "unknown",
            "kev": kev_boost,
        },
        fingerprint=f"vuln:{asset_id}:{cve}:{pkg or '*'}",
        category=["vulnerability", "cve"],
        occurred_at=occurred,
        mitre_techniques=["T1190"],
        mitre_tactics=["TA0001"],
        mitre_confidence=score,
        threat_intel=threat_intel or {},
    )
    return finding.model_dump(mode="json")
