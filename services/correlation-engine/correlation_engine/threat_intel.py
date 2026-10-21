"""Optional threat-intel-service enrichment for correlated incidents."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from correlation_engine.config import settings
from correlation_engine.scoring import FindingView

logger = logging.getLogger("correlation-engine")

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

_CONTEXT_KEYS: dict[str, str] = {
    "dst_ip": "ipv4",
    "src_ip": "ipv4",
    "ip": "ipv4",
    "remote_ip": "ipv4",
    "peer_ip": "ipv4",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "file_hash": "file_hash",
    "sha256": "file_hash",
    "md5": "file_hash",
    "sha1": "file_hash",
    "cve": "cve",
    "ja3": "ja3",
}

# Maximum risk_score increase when threat-intel matches exist.
_MAX_TI_BOOST = 0.15


def extract_observables(findings: list[FindingView]) -> list[dict[str, str]]:
    """Best-effort extract matchable observables from finding context/contributors."""
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []

    def add(otype: str, value: str) -> None:
        value = value.strip()
        if not value:
            return
        normalized = value.lower() if otype in {"file_hash", "domain"} else value
        key = (otype, normalized)
        if key in seen:
            return
        seen.add(key)
        out.append({"type": otype, "value": normalized})

    def walk(obj: Any, depth: int = 0) -> None:
        if depth > 6 or obj is None:
            return
        if isinstance(obj, dict):
            for key, otype in _CONTEXT_KEYS.items():
                if key in obj and obj[key] is not None:
                    add(otype, str(obj[key]))
            for field in ("value", "indicator", "peer"):
                raw = obj.get(field)
                if raw is None or isinstance(raw, (dict, list)):
                    continue
                text = str(raw)
                for m in _IPV4_RE.findall(text):
                    add("ipv4", m)
                for m in _CVE_RE.findall(text):
                    add("cve", m.upper())
                for m in _HASH_RE.findall(text):
                    add("file_hash", m.lower())
                if "://" in text:
                    add("url", text)
                elif _DOMAIN_RE.fullmatch(text.strip()):
                    add("domain", text.strip().lower())
            for nested in obj.values():
                if isinstance(nested, (dict, list)):
                    walk(nested, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, depth + 1)

    for f in findings:
        walk(f.context or {})
        for c in f.contributors or []:
            if isinstance(c, dict):
                walk(c)

    return out


def match_threat_intel(observables: list[dict[str, str]]) -> dict[str, Any] | None:
    """POST /api/v1/match when CORRELATION_THREAT_INTEL_URL is set; else None."""
    base = (settings.threat_intel_url or "").strip()
    if not base or not observables:
        return None
    url = base.rstrip("/") + "/api/v1/match"
    headers: dict[str, str] = {}
    key = (settings.threat_intel_service_key or "").strip()
    if key:
        headers["X-Service-Key"] = key
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(url, json={"observables": observables}, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict):
                return data
    except Exception:
        logger.exception("threat-intel match soft-fail")
    return None


def apply_threat_intel_boost(incident: dict[str, Any], match_result: dict[str, Any] | None) -> None:
    """Boost risk_score by at most +0.15 and attach threat_intel on context."""
    if not match_result:
        return
    matches = match_result.get("matches") or []
    if not matches:
        return

    max_conf = max(int(m.get("confidence") or 0) for m in matches)
    boost = _MAX_TI_BOOST * (max_conf / 100.0) if max_conf > 0 else _MAX_TI_BOOST
    boost = min(_MAX_TI_BOOST, boost)
    incident["risk_score"] = round(min(1.0, float(incident.get("risk_score") or 0.0) + boost), 4)

    ti_block = {
        "matched_indicators": [
            {
                "id": m.get("id"),
                "type": m.get("type"),
                "value": m.get("value"),
                "confidence": m.get("confidence"),
                "source": m.get("source"),
                "tlp": m.get("tlp"),
                "mitre_techniques": m.get("mitre_techniques") or [],
            }
            for m in matches
        ],
        "campaigns": list(match_result.get("campaigns") or []),
        "tlp": match_result.get("tlp"),
    }
    context = dict(incident.get("context") or {})
    context["threat_intel"] = ti_block
    incident["context"] = context
    incident["threat_intel"] = ti_block


def enrich_incident_with_threat_intel(incident: dict[str, Any], findings: list[FindingView]) -> None:
    """No-op when URL unset; otherwise match and boost."""
    if not (settings.threat_intel_url or "").strip():
        return
    observables = extract_observables(findings)
    result = match_threat_intel(observables)
    apply_threat_intel_boost(incident, result)
