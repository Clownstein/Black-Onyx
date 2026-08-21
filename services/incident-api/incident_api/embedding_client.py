"""Shared client for the optional real text-embedding capability."""

from __future__ import annotations

import logging

import httpx

from incident_api.config import settings

logger = logging.getLogger(__name__)


def embed_text(text: str) -> list[float] | None:
    base = (settings.embedding_service_url or "").strip()
    if not base:
        return None
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                f"{base.rstrip('/')}/api/v1/embed/text",
                json={"text": text},
            )
            response.raise_for_status()
            body = response.json()
            if body.get("status") != "ready":
                return None
            vector = body.get("vector")
            if isinstance(vector, list) and vector:
                return [float(value) for value in vector]
    except Exception as exc:  # noqa: BLE001 - caller reports degraded capability state
        logger.warning("embedding service unavailable: %s", exc)
    return None
