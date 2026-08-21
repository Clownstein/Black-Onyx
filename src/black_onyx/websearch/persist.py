"""Persist web-search results into a Qdrant collection."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from qdrant_client.http.models import PointStruct

logger = logging.getLogger(__name__)

# Re-fetching the same URL within this window with byte-identical content skips
# re-embedding and re-upserting; the stored chunks are reused as chat sources.
DEDUPE_WINDOW = timedelta(minutes=15)


def _chunk_text(text: str, chunk_size: int = 1800, overlap: int = 200) -> list[str]:
    text = (text or "").strip()
    if not text:
        return []
    if len(text) <= chunk_size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + chunk_size)
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = max(0, end - overlap)
    return chunks


def _point_id(url: str, chunk_idx: int) -> str:
    digest = hashlib.sha256(f"{url}|{chunk_idx}".encode("utf-8")).hexdigest()
    return str(uuid.UUID(digest[:32]))


def _content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _cached_sources(
    service: Any, collection: str, url: str, content_hash: str
) -> list[dict[str, Any]] | None:
    """Return stored chunks when this URL was fetched recently with identical content."""
    head = service.qdrant_store.get_point(collection, _point_id(url, 0))
    payload = getattr(head, "payload", None) or {}
    if payload.get("content_hash") != content_hash:
        return None
    try:
        fetched_at = datetime.fromisoformat(str(payload.get("fetched_at")))
    except ValueError:
        return None
    if fetched_at.tzinfo is None:
        fetched_at = fetched_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - fetched_at > DEDUPE_WINDOW:
        return None

    total = int(payload.get("total_chunks") or 1)
    sources: list[dict[str, Any]] = []
    for idx in range(total):
        point_id = _point_id(url, idx)
        record = head if idx == 0 else service.qdrant_store.get_point(collection, point_id)
        stored = getattr(record, "payload", None)
        if not stored:
            return None
        sources.append({
            "id": point_id,
            "score": 1.0,
            "payload": stored,
            "collection": collection,
        })
    return sources


def persist_web_document(
    *,
    service: Any,
    collection: str,
    url: str,
    title: str,
    body_text: str,
    snippet: str = "",
    query: str = "",
    source: str,
    session_id: str = "",
) -> list[dict[str, Any]]:
    """Embed and upsert a web document; return source dicts for the chat UI."""
    service.ensure_collection(collection)
    chunks = _chunk_text(body_text or snippet)
    if not chunks:
        chunks = [snippet or title or url]

    content_hash = _content_hash("".join(chunks))
    cached = _cached_sources(service, collection, url, content_hash)
    if cached is not None:
        logger.info("Reused %s cached web chunk(s) for %s", len(cached), url)
        return cached

    embedding_model = service.embedding_model
    vectors = embedding_model.encode(chunks)
    fetched_at = datetime.now(timezone.utc).isoformat()
    points: list[PointStruct] = []
    sources: list[dict[str, Any]] = []

    for idx, (chunk, vector) in enumerate(zip(chunks, vectors)):
        point_id = _point_id(url, idx)
        payload = {
            "source_file": url,
            "body_text": chunk,
            "title": title,
            "url": url,
            "query": query,
            "snippet": snippet,
            "fetched_at": fetched_at,
            "source": source,
            "session_id": session_id,
            "chunk_index": idx,
            "total_chunks": len(chunks),
            "content_hash": content_hash,
        }
        # Collections created via ensure_collection always use a named "text" vector.
        points.append(PointStruct(
            id=point_id,
            vector={"text": list(vector)},
            payload=payload,
        ))
        sources.append({
            "id": point_id,
            "score": 1.0,
            "payload": payload,
            "collection": collection,
        })

    service.qdrant_store.upsert(collection, points)
    logger.info("Persisted %s web chunk(s) for %s into %s", len(points), url, collection)
    return sources
