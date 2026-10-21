"""Semantic evidence search over Qdrant collections (text + optional image)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient

_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"}


def _snippet(payload: dict[str, Any], max_len: int = 240) -> str:
    for key in ("text", "content", "summary", "title", "body"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            text = value.strip()
            return text if len(text) <= max_len else f"{text[: max_len - 3]}..."
    return str(payload)[:max_len]


def _citations(results: list[dict[str, Any]], collection: str) -> list[dict[str, Any]]:
    return [
        {
            "point_id": item.get("id"),
            "collection": item.get("collection") or collection,
            "score": item.get("score"),
            "snippet": _snippet(item.get("payload") or {}),
        }
        for item in results
    ]


async def evidence_search(
    client: PlatformClient,
    *,
    query: str = "",
    collection: str = "all-knowledge",
    limit: int = 10,
    score_threshold: float = 0.0,
    image_path: str = "",
) -> dict[str, Any]:
    if image_path:
        return await _image_search(
            client,
            image_path=image_path,
            collection=collection,
            limit=limit,
            score_threshold=score_threshold,
            query=query,
        )

    if not query.strip():
        raise ValueError("Provide query and/or image_path")

    payload = await client.tip_post(
        "/api/v1/search",
        json={
            "query": query,
            "collection": collection,
            "limit": limit,
            "score_threshold": score_threshold,
        },
    )
    results = payload.get("results") or []
    return {
        "mode": "text",
        "query": query,
        "collection": collection,
        "total": payload.get("total", len(results)),
        "citations": _citations(results, collection),
        "results": results,
    }


async def _image_search(
    client: PlatformClient,
    *,
    image_path: str,
    collection: str,
    limit: int,
    score_threshold: float,
    query: str,
) -> dict[str, Any]:
    path = Path(image_path)
    if not path.is_file():
        raise ValueError(f"image_path not found: {image_path}")
    if path.suffix.lower() not in _IMAGE_SUFFIXES:
        raise ValueError(f"Unsupported image type: {path.suffix}")

    content_type = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".tif": "image/tiff",
        ".tiff": "image/tiff",
    }.get(path.suffix.lower(), "application/octet-stream")

    try:
        payload = await client.tip_post_multipart(
            "/api/v1/search/image",
            files={"image": (path.name, path.read_bytes(), content_type)},
            data={
                "collection": collection,
                "limit": str(limit),
                "score_threshold": str(score_threshold),
            },
        )
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text if exc.response is not None else str(exc)
        if exc.response is not None and exc.response.status_code == 400 and "CLIP" in detail:
            return {
                "mode": "image",
                "enabled": False,
                "query": query,
                "image_path": str(path),
                "collection": collection,
                "message": (
                    "Image search unavailable: CLIP model not installed on TIP. "
                    "Install image dependencies or use text query search."
                ),
                "citations": [],
                "results": [],
                "total": 0,
            }
        raise

    results = payload.get("results") or []
    return {
        "mode": "image",
        "enabled": True,
        "query": query,
        "image_path": str(path),
        "collection": collection,
        "total": payload.get("total", len(results)),
        "citations": _citations(results, collection),
        "results": results,
    }


def register_evidence_search(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_evidence_search")
    async def evidence_search_tool(
        query: str = "",
        collection: str = "all-knowledge",
        limit: int = 10,
        score_threshold: float = 0.0,
        image_path: str = "",
    ) -> dict[str, Any]:
        """Search indexed evidence (text) or optional local image via CLIP when available."""
        return await evidence_search(
            client,
            query=query,
            collection=collection,
            limit=limit,
            score_threshold=score_threshold,
            image_path=image_path,
        )
