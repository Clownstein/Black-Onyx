"""Alias and canary routing helpers."""

from __future__ import annotations

import hashlib
from typing import Literal

from model_gateway.config import settings

ModelName = Literal[
    "log-model", "code-model", "network-model", "metrics-model", "host-state-model"
]
AliasName = Literal["champion", "canary", "shadow"]


def base_url_for_model(model_name: str) -> str:
    mapping = {
        "log-model": settings.log_model_url,
        "log": settings.log_model_url,
        "code-model": settings.code_model_url,
        "code": settings.code_model_url,
        "network-model": settings.network_model_url,
        "network": settings.network_model_url,
        "metrics-model": settings.metrics_model_url,
        "metrics": settings.metrics_model_url,
        "host-state-model": settings.host_state_model_url,
        "host-state": settings.host_state_model_url,
    }
    try:
        return mapping[model_name]
    except KeyError as exc:
        raise ValueError(f"unknown model_name: {model_name}") from exc


def tenant_bucket(tenant_id: str, *, buckets: int = 100) -> int:
    digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % buckets


def select_alias_for_request(
    requested_alias: str | None,
    tenant_id: str,
    *,
    canary_percent: int | None = None,
) -> str:
    """
    Resolve effective serving alias.

    - Explicit shadow/canary/champion honored when provided.
    - Default (champion/None): canary_percent of tenant_ids hashed to canary.
    """
    if requested_alias in {"shadow", "canary", "champion"}:
        return requested_alias
    percent = settings.canary_percent if canary_percent is None else canary_percent
    percent = max(0, min(100, int(percent)))
    if percent <= 0:
        return "champion"
    if tenant_bucket(tenant_id) < percent:
        return "canary"
    return "champion"


def predict_url(model_name: str, alias: str) -> str:
    base = base_url_for_model(model_name).rstrip("/")
    # Model services expose a single predict path; alias is forwarded as a header/query.
    return f"{base}/v1/predict?alias={alias}"
