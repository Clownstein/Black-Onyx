"""Helpers for Qdrant collection naming and default provisioning."""

from __future__ import annotations

import re

COLLECTION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# Known dims avoid loading models just to create empty collections.
_TEXT_DIM_BY_MODEL = {
    "all-mpnet-base-v2": 768,
    "sentence-transformers/all-mpnet-base-v2": 768,
}
_CLIP_DIM_BY_MODEL = {
    "ViT-B-32": 512,
}


def sanitize_collection_name(raw: str) -> str:
    """Normalize an arbitrary label into a valid Qdrant collection name."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", (raw or "").strip())
    cleaned = cleaned.strip("-._") or "unnamed"
    if not cleaned[0].isalnum():
        cleaned = f"c-{cleaned}"
    cleaned = cleaned[:128]
    if not COLLECTION_NAME_RE.match(cleaned):
        raise ValueError(f"Cannot sanitize collection name from {raw!r}")
    return cleaned


def feed_collection_name(feed_name: str) -> str:
    """Collection name for a configured feed (always feed-<sanitized>)."""
    body = sanitize_collection_name(feed_name)
    name = f"feed-{body}"[:128]
    if not COLLECTION_NAME_RE.match(name):
        name = f"feed-{body}"[:123]
        if not name[0].isalnum():
            name = f"f{name[1:]}"
    return name


def detection_collection_name(connector_name: str) -> str:
    """Collection name for a configured detection connector (always detect-<sanitized>).

    Mirrors feed_collection_name exactly — same truncation/prefix-repair
    fallback for the same reason: sanitize_collection_name can return
    something whose "detect-" prefix pushes it over the 128-char cap.
    """
    body = sanitize_collection_name(connector_name)
    name = f"detect-{body}"[:128]
    if not COLLECTION_NAME_RE.match(name):
        name = f"detect-{body}"[:123]
        if not name[0].isalnum():
            name = f"d{name[1:]}"
    return name


def default_text_vector_size(model_name: str) -> int:
    return _TEXT_DIM_BY_MODEL.get(model_name, 768)


def default_clip_vector_size(model_name: str) -> int:
    return _CLIP_DIM_BY_MODEL.get(model_name, 512)
