"""Build unified Finding dicts from model predict responses."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from black_onyx_contracts import Finding, FindingContributor, FindingWindow

MODEL_FINDING_TYPE = {
    "log-model": "log_anomaly",
    "log-transformer": "log_anomaly",
    "network-model": "network_anomaly",
    "metrics-model": "metrics_anomaly",
    "code-model": "code_risk",
    "host-state-model": "host_state_scored",
    "host-state": "host_state_scored",
}


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        text = value.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _window_from_feature(feature_msg: dict[str, Any]) -> FindingWindow:
    start = _parse_dt(feature_msg.get("window_start"))
    end = _parse_dt(feature_msg.get("window_end"))
    if start and end:
        return FindingWindow(start=start, end=end)
    now = datetime.now(UTC)
    return FindingWindow(start=now - timedelta(minutes=5), end=now + timedelta(minutes=5))


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _first_prediction(predict_response: dict[str, Any]) -> dict[str, Any]:
    results = predict_response.get("results") or predict_response.get("predictions")
    if isinstance(results, list) and results:
        first = results[0]
        if isinstance(first, dict):
            return first
    return predict_response


def _extract_score(predict_response: dict[str, Any], prediction: dict[str, Any]) -> tuple[float, float]:
    calibrated = (
        prediction.get("calibrated_score")
        if prediction.get("calibrated_score") is not None
        else predict_response.get("calibrated_score")
    )
    if calibrated is None:
        calibrated = (
            prediction.get("risk_score")
            if prediction.get("risk_score") is not None
            else predict_response.get("risk_score")
        )
    if calibrated is None:
        calibrated = prediction.get("score")
    if calibrated is None:
        calibrated = predict_response.get("score", 0.0)

    raw = prediction.get("raw_score")
    if raw is None:
        raw = predict_response.get("raw_score", calibrated)
    return float(raw), _clamp01(float(calibrated))


def _normalize_contributors(predict_response: dict[str, Any], prediction: dict[str, Any]) -> list[dict[str, Any]]:
    raw = (
        prediction.get("contributors")
        or prediction.get("top_contributors")
        or predict_response.get("contributors")
        or predict_response.get("top_contributors")
        or []
    )
    if not isinstance(raw, list):
        return []

    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        contributor: dict[str, Any] = {
            "type": item.get("type") or item.get("kind") or "contributor",
            "contribution": float(item.get("contribution") or item.get("score") or 0.0),
        }
        if item.get("template_id") is not None:
            contributor["template_id"] = str(item["template_id"])
        elif item.get("observed_template") is not None:
            contributor["template_id"] = str(item["observed_template"])
        if item.get("position") is not None:
            try:
                contributor["position"] = int(item["position"])
            except (TypeError, ValueError):
                pass
        if item.get("summary") is not None:
            contributor["summary"] = str(item["summary"])
        elif item.get("metric") is not None:
            contributor["summary"] = str(item["metric"])
        # Keep extra keys for FindingContributor(extra="allow")
        for key, value in item.items():
            if key not in contributor:
                contributor[key] = value
        out.append(contributor)
    return out


def _severity_hint(score: float, predict_response: dict[str, Any], prediction: dict[str, Any]) -> str | None:
    explicit = prediction.get("severity") or predict_response.get("severity")
    if isinstance(explicit, str) and explicit in {"low", "medium", "high", "critical"}:
        return explicit
    if score >= 0.93:
        return "critical"
    if score >= 0.80:
        return "high"
    if score >= 0.60:
        return "medium"
    return "low"


def _top_contributor_key(contributors: list[dict[str, Any]]) -> str:
    if not contributors:
        return "none"
    top = max(contributors, key=lambda c: float(c.get("contribution") or 0.0))
    return str(
        top.get("template_id")
        or top.get("summary")
        or top.get("metric")
        or top.get("type")
        or "none"
    )


def _fingerprint(tenant_id: str, asset_id: str, finding_type: str, contributors: list[dict[str, Any]]) -> str:
    material = f"{tenant_id}|{asset_id}|{finding_type}|{_top_contributor_key(contributors)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _asset_and_service(feature_msg: dict[str, Any], predict_body: dict[str, Any] | None = None) -> tuple[str, str | None]:
    features = {}
    if predict_body and isinstance(predict_body.get("features"), dict):
        features = predict_body["features"]
    asset = feature_msg.get("asset")
    asset_id = (
        (asset.get("asset_id") if isinstance(asset, dict) else None)
        or feature_msg.get("asset_id")
        or features.get("asset_id")
        or "unknown"
    )
    service_id = (
        (asset.get("service_id") if isinstance(asset, dict) else None)
        or feature_msg.get("service_id")
        or features.get("service_id")
    )
    return str(asset_id), (str(service_id) if service_id else None)


def build_finding(
    model_name: str,
    feature_msg: dict[str, Any],
    predict_response: dict[str, Any],
    *,
    predict_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a Finding-compatible dict from a model response and feature envelope."""
    prediction = _first_prediction(predict_response)
    raw_score, calibrated_score = _extract_score(predict_response, prediction)
    contributors = _normalize_contributors(predict_response, prediction)
    finding_type = MODEL_FINDING_TYPE.get(model_name, "anomaly")
    tenant_id = str(
        feature_msg.get("tenant_id")
        or predict_response.get("tenant_id")
        or (predict_body or {}).get("tenant_id")
        or "default"
    )
    asset_id, service_id = _asset_and_service(feature_msg, predict_body)
    model_version = str(
        prediction.get("model_version")
        or predict_response.get("model_version")
        or "0.0.0"
    )
    feature_version = (
        feature_msg.get("feature_version")
        or predict_response.get("feature_version")
        or (predict_body or {}).get("feature_version")
    )
    window = _window_from_feature(feature_msg)
    fingerprint = _fingerprint(tenant_id, asset_id, finding_type, contributors)

    categories: list[str] = []
    risk_categories = predict_response.get("risk_categories") or prediction.get("risk_categories")
    if isinstance(risk_categories, list):
        categories = [str(c) for c in risk_categories]

    ctx: dict[str, Any] = {
        "request_id": (predict_body or {}).get("request_id") or predict_response.get("request_id"),
        "source_event_type": feature_msg.get("event_type"),
        "routed_alias": predict_response.get("routed_alias"),
    }
    # Propagate correlation / evidence linkage fields from feature envelopes.
    for key in (
        "deployment_id",
        "commit",
        "deployment_age_minutes",
        "deployment_commit_matches",
        "known_maintenance",
        "deterministic_security_indicator",
        "log_category",
        "code_category",
        "new_external_peer",
        "title",
        "summary",
    ):
        if feature_msg.get(key) is not None:
            ctx[key] = feature_msg[key]
    nested_ctx = feature_msg.get("context")
    if isinstance(nested_ctx, dict):
        for key, value in nested_ctx.items():
            ctx.setdefault(key, value)

    finding_id = _stable_finding_id(
        feature_msg,
        fingerprint=fingerprint,
        window=window,
    )

    finding = Finding(
        finding_id=finding_id,
        tenant_id=tenant_id,
        finding_type=finding_type,
        asset_id=asset_id,
        service_id=service_id,
        model_name=str(predict_response.get("model_name") or model_name),
        model_version=model_version,
        feature_version=str(feature_version) if feature_version else None,
        raw_score=float(raw_score),
        calibrated_score=calibrated_score,
        severity_hint=_severity_hint(calibrated_score, predict_response, prediction),  # type: ignore[arg-type]
        window=window,
        contributors=[FindingContributor.model_validate(c) for c in contributors],
        evidence_refs=list(feature_msg.get("evidence_refs") or []),
        context=ctx,
        fingerprint=fingerprint,
        category=categories,
        occurred_at=_parse_dt(feature_msg.get("window_end") or feature_msg.get("occurred_at")),
    )
    return finding.model_dump(mode="json")


def _stable_finding_id(
    feature_msg: dict[str, Any],
    *,
    fingerprint: str,
    window: FindingWindow,
) -> str:
    """Prefer explicit ids; otherwise hash fingerprint+window for retry idempotency."""
    for key in ("finding_id", "idempotency_key", "feature_id"):
        value = feature_msg.get(key)
        if value:
            return str(value)
    material = f"{fingerprint}|{window.start.isoformat()}|{window.end.isoformat()}"
    return "fnd-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]

def normalize_code_finding(msg: dict[str, Any]) -> dict[str, Any]:
    """Normalize a code.findings advisory payload into findings.code Finding shape."""
    scanner_findings = msg.get("scanner_findings") if isinstance(msg.get("scanner_findings"), list) else []
    contributors: list[dict[str, Any]] = []
    for idx, finding in enumerate(scanner_findings[:10]):
        if not isinstance(finding, dict):
            continue
        contributors.append(
            {
                "type": str(finding.get("type") or finding.get("check_id") or "scanner"),
                "contribution": float(finding.get("score") or finding.get("severity_score") or 0.5),
                "summary": str(finding.get("message") or finding.get("rule") or finding.get("path") or "finding"),
                "position": idx,
            }
        )

    advisory_response = {
        "model_name": "code-model",
        "model_version": str(msg.get("model_version") or "advisory"),
        "calibrated_score": float(msg.get("calibrated_score") or msg.get("risk_score") or 0.5),
        "raw_score": float(msg.get("raw_score") or msg.get("risk_score") or 0.5),
        "contributors": contributors,
        "risk_categories": msg.get("risk_categories") or ["code_advisory"],
    }
    feature_msg = {
        **msg,
        "feature_version": msg.get("feature_version") or "code.features.v1",
        "window_start": msg.get("window_start") or msg.get("occurred_at"),
        "window_end": msg.get("window_end") or msg.get("occurred_at"),
    }
    finding = build_finding("code-model", feature_msg, advisory_response)
    finding["finding_type"] = "code_risk"
    finding["context"] = {
        **(finding.get("context") or {}),
        "advisory_only": bool(msg.get("advisory_only", True)),
        "normalized_from": "code.findings",
        "scanners": msg.get("scanners"),
    }
    return finding
