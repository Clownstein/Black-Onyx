"""Cached view of the training orchestrator's confirmed serving state."""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from model_gateway.config import settings

logger = logging.getLogger("model-gateway")
_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}


def _canonical(model_name: str) -> str:
    return model_name if model_name.endswith("-model") else f"{model_name}-model"


async def serving_aliases(model_name: str, tenant_id: str) -> dict[str, Any] | None:
    """Return fresh tenant serving evidence, or None when it is unavailable."""
    if not settings.training_orchestrator_url:
        return None
    name = _canonical(model_name)
    now = time.monotonic()
    cache_key = (tenant_id, name)
    cached = _cache.get(cache_key)
    if cached and now - cached[0] < settings.serving_state_ttl_seconds:
        return cached[1]
    headers = {
        "X-API-Key": settings.training_api_key,
        "X-Tenant-Id": tenant_id,
    }
    try:
        async with httpx.AsyncClient(timeout=2.0, trust_env=False) as client:
            response = await client.get(
                f"{settings.training_orchestrator_url.rstrip('/')}/api/v1/serving/{name}", headers=headers,
            )
            response.raise_for_status()
            document = response.json()
            if (
                not isinstance(document, dict)
                or document.get("tenant_id") != tenant_id
                or document.get("model_name") != name
            ):
                logger.warning("serving state identity mismatch for %s", name)
                return None
            aliases = document.get("aliases")
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("serving state unavailable for %s: %s", name, exc)
        if cached and now - cached[0] <= settings.serving_state_max_stale_seconds:
            # Keep expectations for diagnostics during an outage, but stale
            # replica confirmations must never authorize a prediction.
            return {
                alias: {**value, "confirmed": False, "detail": "serving confirmation is stale"}
                for alias, value in cached[1].items()
            }
        return None
    if not isinstance(aliases, dict):
        return None
    # Do not let malformed or incomplete orchestrator data authorize routing.
    # The report ties a signed package to a particular desired-state generation.
    normalized: dict[str, Any] = {}
    for alias, state in aliases.items():
        if alias not in {"champion", "canary", "shadow"} or not isinstance(state, dict):
            return None
        if state.get("removed") is True:
            generation = state.get("generation")
            if (
                isinstance(generation, bool)
                or not isinstance(generation, int)
                or generation < 1
                or not isinstance(state.get("confirmed"), bool)
            ):
                return None
            # A removed alias is valid serving state, but cannot be routed.
            continue
        version = state.get("version")
        signature = state.get("signature")
        generation = state.get("generation")
        if (
            not isinstance(version, str)
            or not version.strip()
            or not isinstance(signature, str)
            or not signature.strip()
            or isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 1
            or not isinstance(state.get("confirmed"), bool)
        ):
            return None
        normalized[alias] = dict(state)
    _cache[cache_key] = (now, normalized)
    return normalized


def _confirmed_package(state: Any) -> bool:
    return bool(
        isinstance(state, dict)
        and state.get("confirmed") is True
        and isinstance(state.get("version"), str)
        and state["version"].strip()
        and isinstance(state.get("signature"), str)
        and state["signature"].strip()
        and isinstance(state.get("generation"), int)
        and not isinstance(state.get("generation"), bool)
        and state["generation"] > 0
    )


def effective_alias(requested: str, aliases: dict[str, Any] | None) -> str | None:
    """Route only to a package with fresh replica confirmation."""
    if aliases is None:
        return None
    if requested == "champion":
        target = aliases.get("champion")
        return "champion" if _confirmed_package(target) else None
    target = aliases.get(requested)
    if _confirmed_package(target):
        return requested
    champion = aliases.get("champion")
    return "champion" if _confirmed_package(champion) else None


def verify_version(alias: str, result: dict[str, Any], aliases: dict[str, Any] | None) -> dict[str, Any]:
    expected = (aliases or {}).get(alias, {}).get("version") if aliases else None
    served = result.get("model_version")
    verified = expected is not None and served == expected
    if expected is not None and not verified:
        logger.warning("alias %s served %s but %s is desired", alias, served, expected)
    return {"expected_version": expected, "served_version": served, "version_verified": verified}


def reset_cache() -> None:
    _cache.clear()
