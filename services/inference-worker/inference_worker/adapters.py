"""Convert feature topic payloads into model-gateway / model-native predict bodies."""

from __future__ import annotations

from typing import Any
from ulid import ULID


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _tenant_id(msg: dict[str, Any]) -> str:
    return str(msg.get("tenant_id") or (msg.get("envelope") or {}).get("tenant_id") or "default")


def _asset_id(msg: dict[str, Any]) -> str:
    asset = msg.get("asset")
    if isinstance(asset, dict) and asset.get("asset_id"):
        return str(asset["asset_id"])
    if msg.get("asset_id"):
        return str(msg["asset_id"])
    return "unknown"


def _service_id(msg: dict[str, Any]) -> str | None:
    asset = msg.get("asset")
    if isinstance(asset, dict) and asset.get("service_id"):
        return str(asset["service_id"])
    value = msg.get("service_id")
    return str(value) if value else None


def _request_id(msg: dict[str, Any]) -> str:
    for key in ("request_id", "sequence_id", "event_id", "idempotency_key"):
        if msg.get(key):
            return str(msg[key])
    return str(ULID())


def _feature_version(msg: dict[str, Any], default: str = "1.0") -> str:
    return str(msg.get("feature_version") or default)


def _wrap_gateway(
    *,
    model_name: str,
    tenant_id: str,
    request_id: str,
    feature_version: str,
    features: dict[str, Any],
    model_request: dict[str, Any],
    items: list[dict[str, Any]] | None = None,
    batch: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a gateway PredictRequest that also carries a native model_request."""
    body: dict[str, Any] = {
        "model_name": model_name,
        "tenant_id": tenant_id,
        "request_id": request_id,
        "feature_version": feature_version,
        "features": features,
        "model_request": model_request,
        "asset_id": features.get("asset_id"),
        "service_id": features.get("service_id"),
    }
    if items is not None:
        body["items"] = items
    if batch is not None:
        body["batch"] = batch
    return body


def adapt_log_features(feature_msg: dict[str, Any]) -> dict[str, Any]:
    """LogFeatureSequence → log-model predict body (+ gateway wrapper)."""
    msg = dict(feature_msg)
    tenant_id = _tenant_id(msg)
    asset_id = _asset_id(msg)
    service_id = _service_id(msg)
    request_id = _request_id(msg)
    feature_version = _feature_version(msg, "1.0")

    events = msg.get("events") or msg.get("sequence") or []
    template_ids: list[str] = []
    normalized_events: list[dict[str, Any]] = []
    if isinstance(events, list):
        for event in events:
            if isinstance(event, str):
                template_ids.append(event)
                normalized_events.append({"template_id": event, "severity": "INFO"})
                continue
            if not isinstance(event, dict):
                continue
            tid = event.get("template_id") or event.get("template") or event.get("id")
            if tid is None and "sequence" in event:
                continue
            tid_str = str(tid) if tid is not None else "[UNK]"
            template_ids.append(tid_str)
            normalized_events.append(
                {
                    "template_id": tid_str,
                    "severity": event.get("severity") or "INFO",
                    "event_id": event.get("event_id"),
                    "occurred_at": event.get("occurred_at"),
                    "logger": event.get("logger"),
                }
            )

    if not normalized_events and isinstance(msg.get("template_ids"), list):
        for tid in msg["template_ids"]:
            tid_str = str(tid)
            template_ids.append(tid_str)
            normalized_events.append({"template_id": tid_str, "severity": "INFO"})

    if not normalized_events:
        # Synthesize a minimal valid sequence so the model can still respond.
        normalized_events = [{"template_id": "[UNK]", "severity": "INFO"}]
        template_ids = ["[UNK]"]

    item = {
        "sequence_id": msg.get("sequence_id") or request_id,
        "events": normalized_events,
        "template_ids": template_ids,
        "asset_id": asset_id,
        "service_id": service_id,
    }
    items = [item]
    model_request = {
        "request_id": request_id,
        "tenant_id": tenant_id,
        "model_name": "log-model",
        "feature_version": feature_version,
        "items": items,
    }
    features = {
        "asset_id": asset_id,
        "service_id": service_id,
        "sequence_id": item["sequence_id"],
        "template_ids": template_ids,
        "events": normalized_events,
        "window_start": msg.get("window_start"),
        "window_end": msg.get("window_end"),
    }
    return _wrap_gateway(
        model_name="log-model",
        tenant_id=tenant_id,
        request_id=request_id,
        feature_version=feature_version,
        features=features,
        model_request=model_request,
        items=items,
        batch=items,
    )


def adapt_network_features(msg: dict[str, Any]) -> dict[str, Any]:
    """Network window features → network-model predict body."""
    tenant_id = _tenant_id(msg)
    asset_id = _asset_id(msg)
    service_id = _service_id(msg)
    request_id = _request_id(msg)
    feature_version = _feature_version(msg, "network.features.v1")

    flows = msg.get("flows") or msg.get("flow_sample") or []
    if not isinstance(flows, list):
        flows = []
    detections = msg.get("detections") if isinstance(msg.get("detections"), list) else []
    aggregates = _as_dict(msg.get("aggregates"))

    if not flows and not detections and not aggregates:
        # Minimal valid request from whatever keys exist.
        aggregates = {
            "event_count": int(msg.get("event_count") or 0),
            "distinct_peers": int(msg.get("distinct_peers") or 0),
        }

    model_request = {
        "flows": flows,
        "detections": detections,
        "aggregates": aggregates,
    }
    features = {
        "asset_id": asset_id,
        "service_id": service_id,
        "flows": flows,
        "detections": detections,
        "aggregates": aggregates,
        "window_start": msg.get("window_start"),
        "window_end": msg.get("window_end"),
    }
    return _wrap_gateway(
        model_name="network-model",
        tenant_id=tenant_id,
        request_id=request_id,
        feature_version=feature_version,
        features=features,
        model_request=model_request,
    )


def adapt_metrics_features(msg: dict[str, Any]) -> dict[str, Any]:
    """Metrics window features → metrics-model predict body."""
    tenant_id = _tenant_id(msg)
    asset_id = _asset_id(msg)
    service_id = _service_id(msg)
    request_id = _request_id(msg)
    feature_version = _feature_version(msg, "metrics.features.v1")

    values = msg.get("values")
    missingness = msg.get("missingness") if isinstance(msg.get("missingness"), dict) else {}

    # Accept a 2d array under "values" as list[list[float]] with positional metric names.
    if isinstance(values, list):
        mapped: dict[str, list[float]] = {}
        for idx, row in enumerate(values):
            if isinstance(row, (int, float)):
                mapped.setdefault("m0", []).append(float(row))
            elif isinstance(row, list):
                mapped[f"m{idx}"] = [float(x) for x in row if isinstance(x, (int, float))]
        values = mapped
    elif not isinstance(values, dict):
        values = {}

    if not values:
        # Flat metrics dict like {"cpu": 0.1, "mem": 0.2} → length-1 series.
        flat = {
            k: float(v)
            for k, v in msg.items()
            if isinstance(v, (int, float)) and k not in {"missing_fraction", "window_length", "stride"}
        }
        if flat:
            values = {k: [v] for k, v in flat.items()}
        else:
            values = {"m0": [0.0]}

    model_request = {
        "values": values,
        "missingness": missingness,
        "profile": str(msg.get("profile") or "web_service_v1"),
        "missing_fraction": msg.get("missing_fraction"),
    }
    features = {
        "asset_id": asset_id,
        "service_id": service_id,
        **model_request,
        "window_start": msg.get("window_start"),
        "window_end": msg.get("window_end"),
    }
    return _wrap_gateway(
        model_name="metrics-model",
        tenant_id=tenant_id,
        request_id=request_id,
        feature_version=feature_version,
        features=features,
        model_request=model_request,
    )


def adapt_code_features(msg: dict[str, Any]) -> dict[str, Any]:
    """Code feature record → code-model predict body."""
    tenant_id = _tenant_id(msg)
    asset_id = _asset_id(msg)
    service_id = _service_id(msg)
    request_id = _request_id(msg)
    feature_version = _feature_version(msg, "code.features.v1")

    text_features = _as_dict(msg.get("text_features"))
    diff_text = str(
        msg.get("diff_text")
        or text_features.get("diff_text")
        or msg.get("diff")
        or msg.get("patch")
        or ""
    )
    scanner_findings = msg.get("scanner_findings")
    if not isinstance(scanner_findings, list):
        scanner_findings = []

    files_changed = msg.get("files_changed")
    if not isinstance(files_changed, list):
        path = msg.get("path")
        files_changed = [str(path)] if path else []

    path = str(msg.get("path") or (files_changed[0] if files_changed else ""))
    language = msg.get("language")

    model_request = {
        "diff_text": diff_text,
        "files_changed": files_changed,
        "diff_stats": _as_dict(msg.get("diff_stats")),
        "scanner_findings": scanner_findings,
        "text_features": {**text_features, "diff_text": diff_text or text_features.get("diff_text", "")},
        "changed_symbols": msg.get("changed_symbols")
        if isinstance(msg.get("changed_symbols"), list)
        else [],
        "path": path,
        "language": language,
    }
    features = {
        "asset_id": asset_id,
        "service_id": service_id,
        **model_request,
    }
    return _wrap_gateway(
        model_name="code-model",
        tenant_id=tenant_id,
        request_id=request_id,
        feature_version=feature_version,
        features=features,
        model_request=model_request,
    )


def adapt_host_state_features(feature_msg: dict[str, Any]) -> dict[str, Any]:
    """host-state.features window → host-state-model predict body."""
    msg = dict(feature_msg)
    tenant_id = _tenant_id(msg)
    asset_id = _asset_id(msg)
    service_id = _service_id(msg)
    request_id = _request_id(msg)
    feature_version = _feature_version(msg, "host-state.features.v1")

    detections = msg.get("detections") if isinstance(msg.get("detections"), list) else []
    process_events = (
        msg.get("process_events") if isinstance(msg.get("process_events"), list) else []
    )
    item: dict[str, Any] = {
        "sequence_id": request_id,
        "asset_id": asset_id,
        "service_id": service_id,
        "detections": detections,
        "rule_hits": detections,
        "process_events": process_events,
        "event_count": msg.get("event_count") or len(process_events),
        "window_start": msg.get("window_start"),
        "window_end": msg.get("window_end"),
    }
    # Prefer explicit scores on the feature envelope when present.
    for key in ("calibrated_score", "risk_score", "score", "anomaly_score", "severity"):
        if msg.get(key) is not None:
            item[key] = msg[key]

    features = {
        "asset_id": asset_id,
        "service_id": service_id,
        "detections": detections,
        "process_events": process_events,
        "event_count": item["event_count"],
    }
    model_request = {
        "items": [item],
        "feature_version": feature_version,
    }
    return _wrap_gateway(
        model_name="host-state-model",
        tenant_id=tenant_id,
        request_id=request_id,
        feature_version=feature_version,
        features=features,
        model_request=model_request,
        items=[item],
    )


ADAPTERS = {
    "log-model": adapt_log_features,
    "network-model": adapt_network_features,
    "metrics-model": adapt_metrics_features,
    "code-model": adapt_code_features,
    "host-state-model": adapt_host_state_features,
    "host-state": adapt_host_state_features,
}


def adapt_features(model_name: str, feature_msg: dict[str, Any]) -> dict[str, Any]:
    try:
        adapter = ADAPTERS[model_name]
    except KeyError as exc:
        raise ValueError(f"no adapter for model_name={model_name}") from exc
    return adapter(feature_msg)


def direct_predict_body(gateway_body: dict[str, Any]) -> dict[str, Any]:
    """Prefer model_request for direct upstream calls; fall back to merged fields."""
    model_request = gateway_body.get("model_request")
    if isinstance(model_request, dict) and model_request:
        return dict(model_request)

    body: dict[str, Any] = {
        "request_id": gateway_body.get("request_id") or str(ULID()),
        "tenant_id": gateway_body.get("tenant_id"),
        "model_name": gateway_body.get("model_name"),
        "feature_version": gateway_body.get("feature_version") or "1.0",
    }
    features = gateway_body.get("features") if isinstance(gateway_body.get("features"), dict) else {}
    body.update(features)
    items = gateway_body.get("items") or gateway_body.get("batch")
    if items:
        body["items"] = items
    return body
