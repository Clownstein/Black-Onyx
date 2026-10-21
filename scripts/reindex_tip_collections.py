#!/usr/bin/env python3
"""Re-index TIP Qdrant collections after switching to Qwen3/Ollama embeddings.

Modes:
  1. Qdrant scroll (default): re-embed existing payloads into a new collection.
  2. --from-ingest-dir: re-chunk and re-embed source files via Ingestor.

Usage:
    uv run python scripts/reindex_tip_collections.py --source all-knowledge --target all-knowledge-qwen3
    uv run python scripts/reindex_tip_collections.py --source all-knowledge --target all-knowledge-qwen3 --dry-run
    uv run python scripts/reindex_tip_collections.py --source feed-A --source feed-B --target all-knowledge-qwen3
    uv run python scripts/reindex_tip_collections.py --from-ingest-dir ./data --target all-knowledge-qwen3
    uv run python scripts/reindex_tip_collections.py --source all-knowledge --target all-knowledge-qwen3 --config config.yaml
"""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from pathlib import Path
from typing import Any, Iterator

from qdrant_client.http.models import PointStruct

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def _iter_scroll_batches(
    store: Any,
    collection: str,
    batch_size: int = 100,
    *,
    with_vectors: bool = False,
) -> Iterator[list[Any]]:
    offset = None
    while True:
        batch, offset = store._client.scroll(
            collection_name=collection,
            limit=batch_size,
            offset=offset,
            with_payload=True,
            with_vectors=with_vectors,
        )
        if not batch:
            break
        yield batch
        if offset is None:
            break


def _point_vector_dict(point: Any, text_vector: list[float]) -> dict[str, list[float]] | list[float]:
    """Rebuild named vectors, re-embedding text while preserving clip when present."""
    existing = getattr(point, "vector", None)
    if isinstance(existing, dict):
        out: dict[str, list[float]] = {"text": text_vector}
        clip = existing.get("clip")
        if isinstance(clip, list) and clip:
            out["clip"] = clip
        return out
    return {"text": text_vector}


def _collection_point_count(store: Any, collection: str) -> int:
    info = store._client.get_collection(collection)
    return int(getattr(info, "points_count", None) or 0)


def _stable_point_id(source: str, original_id: Any) -> str:
    """Namespace IDs when merging multiple sources into one target."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{source}:{original_id}"))


def _build_store_and_embedder(config_path: str | None) -> tuple[Any, Any, Any]:
    from black_onyx.config import get_settings
    from black_onyx.core.embeddings import create_embedding_model
    from black_onyx.core.qdrant_store import QdrantStore

    if config_path:
        get_settings.cache_clear()
    settings = get_settings(config_path=config_path)

    api_key = None
    if settings.qdrant.api_key:
        api_key = settings.qdrant.api_key.get_secret_value()

    store = QdrantStore(
        host=settings.qdrant.host,
        port=settings.qdrant.port,
        api_key=api_key,
        prefer_grpc=settings.qdrant.prefer_grpc,
        https=settings.qdrant.https,
        timeout=settings.qdrant.timeout,
    )
    embedder = create_embedding_model(
        settings.embedding,
        device=settings.resolve_device(settings.embedding.device),
    )
    return settings, store, embedder


def reindex_from_qdrant(
    *,
    sources: list[str],
    target: str,
    config_path: str | None,
    dry_run: bool,
    batch_size: int,
) -> int:
    settings, store, embedder = _build_store_and_embedder(config_path)

    for source in sources:
        if not store._client.collection_exists(source):
            raise SystemExit(f"Source collection '{source}' does not exist")

    text_dim = embedder.get_embedding_dim()
    clip_dim = 512
    use_multivector = settings.image.use_multivector
    namespace_ids = len(sources) > 1

    logger.info(
        "Re-index %s -> %s using backend=%s model=%s dim=%s (qdrant-scroll)",
        ",".join(sources),
        target,
        getattr(embedder, "backend", settings.embedding.backend),
        embedder.model_name,
        text_dim,
    )

    if dry_run:
        total = sum(_collection_point_count(store, source) for source in sources)
        logger.info("Dry run: would re-index %d points from %d source(s)", total, len(sources))
        return total

    store.ensure_collection(
        collection_name=target,
        text_vector_size=text_dim,
        clip_vector_size=clip_dim,
        use_multivector=use_multivector,
    )

    encode_docs = getattr(embedder, "encode", None)
    encode_doc = getattr(embedder, "encode_document", embedder.encode_single)
    reindexed = 0

    for source in sources:
        logger.info("Scrolling source '%s'...", source)
        for batch in _iter_scroll_batches(
            store, source, batch_size=batch_size, with_vectors=True
        ):
            bodies: list[str] = []
            kept: list[Any] = []
            for point in batch:
                payload = dict(point.payload or {})
                body = payload.get("body_text") or payload.get("text") or ""
                if not body:
                    logger.debug("Skipping point %s: no body_text", point.id)
                    continue
                bodies.append(body)
                kept.append(point)

            if not bodies:
                continue

            if encode_docs is not None:
                vectors = encode_docs(bodies, batch_size=batch_size)
            else:
                vectors = [encode_doc(body) for body in bodies]

            pending: list[PointStruct] = []
            for point, text_vector in zip(kept, vectors, strict=True):
                payload = dict(point.payload or {})
                payload["reindex_source_collection"] = source
                point_id: Any = (
                    _stable_point_id(source, point.id) if namespace_ids else point.id
                )
                pending.append(
                    PointStruct(
                        id=point_id,
                        vector=_point_vector_dict(point, text_vector),
                        payload=payload,
                    )
                )

            store.upsert(target, pending)
            reindexed += len(pending)
            logger.info("Re-indexed %d points...", reindexed)

    logger.info("Done: re-indexed %d points into '%s'", reindexed, target)
    return reindexed


def reindex_from_ingest_dir(
    *,
    target: str,
    ingest_dir: Path,
    config_path: str | None,
    dry_run: bool,
) -> int:
    """Re-chunk and re-embed files from an ingest directory into target."""
    from black_onyx.pipeline.ingestor import Ingestor
    from black_onyx.pipeline.progress import ProgressTracker

    settings, store, embedder = _build_store_and_embedder(config_path)
    directory = ingest_dir.resolve()
    if not directory.is_dir():
        raise SystemExit(f"Ingest directory does not exist: {directory}")

    files = [p for p in directory.rglob("*") if p.is_file()]
    logger.info(
        "Re-index from ingest dir %s -> %s (%d files) backend=%s dim=%s",
        directory,
        target,
        len(files),
        getattr(embedder, "backend", settings.embedding.backend),
        embedder.get_embedding_dim(),
    )
    if dry_run:
        logger.info("Dry run: would ingest %d files into '%s'", len(files), target)
        return len(files)

    store.ensure_collection(
        collection_name=target,
        text_vector_size=embedder.get_embedding_dim(),
        clip_vector_size=512,
        use_multivector=settings.image.use_multivector,
    )

    tracker = ProgressTracker()
    ingestor = Ingestor(
        embedding_model=embedder,
        ner_model=None,
        classifier=None,
        qdrant_store=store,
        ocr_engine=None,
        clip_model=None,
        chunk_size=settings.chunking.chunk_size,
        chunk_overlap=settings.chunking.chunk_overlap,
        sentence_aware=settings.chunking.sentence_aware,
        batch_size=settings.ingestion.batch_size,
        max_workers=settings.ingestion.max_workers,
        enable_ner=False,
        enable_classifier=False,
        enable_code_detection=settings.ingestion.enable_code_detection,
        enable_image_extraction=False,
        use_multivector=settings.image.use_multivector,
        csv_path=settings.ingestion.csv_path,
    )
    stats = ingestor.process_directory(
        directory=str(directory),
        collection_name=target,
        progress_tracker=tracker,
        checkpoint_manager=None,
    )
    chunks = int(stats.get("total_chunks") or 0)
    logger.info("Done: ingested %d chunks into '%s' (%s)", chunks, target, stats)
    return chunks


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-index TIP collections for new embedder")
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Source Qdrant collection (repeatable; scroll mode)",
    )
    parser.add_argument("--target", required=True, help="Target Qdrant collection name")
    parser.add_argument("--config", default=None, help="Path to config.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Count work only")
    parser.add_argument("--batch-size", type=int, default=32, help="Scroll/embed/upsert batch size")
    parser.add_argument(
        "--from-ingest-dir",
        type=Path,
        default=None,
        help="Re-chunk/re-embed files from this directory into --target (skips Qdrant scroll)",
    )
    args = parser.parse_args()

    try:
        if args.from_ingest_dir is not None:
            reindex_from_ingest_dir(
                target=args.target,
                ingest_dir=args.from_ingest_dir,
                config_path=args.config,
                dry_run=args.dry_run,
            )
        else:
            if not args.source:
                raise SystemExit("--source is required unless --from-ingest-dir is set")
            reindex_from_qdrant(
                sources=args.source,
                target=args.target,
                config_path=args.config,
                dry_run=args.dry_run,
                batch_size=args.batch_size,
            )
    except SystemExit:
        raise
    except Exception as exc:
        logger.error("Re-index failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
