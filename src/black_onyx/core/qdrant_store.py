"""Qdrant store wrapper — collection management, upsert, search, scroll with multi-vector support."""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Any, Optional, cast
from urllib.parse import quote

from qdrant_client import QdrantClient
from qdrant_client.http.models import (
    Distance,
    Filter,
    PointStruct,
    VectorParams,
)

logger = logging.getLogger(__name__)


class QdrantStore:
    """Wrapper around QdrantClient with multi-vector (named vectors) support."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6333,
        api_key: Optional[str] = None,
        prefer_grpc: bool = False,
        https: bool = False,
        timeout: int = 30,
        retries: int = 3,
    ) -> None:
        """Initialize the Qdrant client connection.

        Args:
            host: Qdrant server host.
            port: Qdrant server port.
            api_key: Optional API key for Qdrant Cloud.
            prefer_grpc: Use gRPC protocol for better performance.
            timeout: Connection timeout in seconds.
            retries: Number of connection retry attempts.
        """
        kwargs: dict[str, Any] = {
            "host": host,
            "port": port,
            "timeout": timeout,
            "prefer_grpc": prefer_grpc,
            "https": https,
            "check_compatibility": False,
        }
        if api_key:
            kwargs["api_key"] = api_key
        self._host = host
        self._port = port
        self._api_key = api_key
        self._https = https

        last_error: Exception | None = None
        for attempt in range(retries):
            try:
                self._client = QdrantClient(**kwargs)
                # Test connection
                self._client.get_collections()
                logger.info(f"Connected to Qdrant at {host}:{port}")
                break
            except Exception as e:
                last_error = e
                logger.warning(f"Qdrant connection attempt {attempt + 1}/{retries} failed: {e}")
                time.sleep(2 ** attempt)
        else:
            raise ConnectionError(f"Failed to connect to Qdrant after {retries} attempts: {last_error}")

    @property
    def client(self) -> QdrantClient:
        return self._client

    def _http_base(self) -> str:
        scheme = "https" if self._https else "http"
        return f"{scheme}://{self._host}:{self._port}"

    def _http_headers(self) -> dict[str, str]:
        if self._api_key:
            return {"api-key": self._api_key}
        return {}

    def create_and_download_snapshot(self, collection_name: str, destination: Path) -> dict[str, Any]:
        """Create a collection snapshot on the server and download it to ``destination``."""
        import httpx

        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        created = self._client.create_snapshot(collection_name=collection_name)
        snap_name = getattr(created, "name", None) or str(created)
        url = (
            f"{self._http_base()}/collections/{quote(collection_name, safe='')}"
            f"/snapshots/{quote(snap_name, safe='')}"
        )
        with httpx.Client(timeout=300.0) as http:
            with http.stream("GET", url, headers=self._http_headers()) as resp:
                resp.raise_for_status()
                with destination.open("wb") as handle:
                    for chunk in resp.iter_bytes():
                        handle.write(chunk)
        return {
            "collection": collection_name,
            "snapshot": snap_name,
            "path": str(destination),
            "bytes": destination.stat().st_size,
        }

    def upload_and_recover_snapshot(self, collection_name: str, snapshot_path: Path) -> dict[str, Any]:
        """Upload a local snapshot file and recover the collection from it."""
        import httpx

        snapshot_path = Path(snapshot_path)
        if not snapshot_path.is_file():
            raise FileNotFoundError(f"Snapshot not found: {snapshot_path}")
        url = (
            f"{self._http_base()}/collections/{quote(collection_name, safe='')}"
            f"/snapshots/upload?priority=snapshot"
        )
        with httpx.Client(timeout=600.0) as http:
            with snapshot_path.open("rb") as handle:
                resp = http.post(
                    url,
                    headers=self._http_headers(),
                    files={"snapshot": (snapshot_path.name, handle, "application/octet-stream")},
                )
            resp.raise_for_status()
            body = resp.json() if resp.content else {}
        return {
            "collection": collection_name,
            "status": "recovered",
            "result": body.get("result") if isinstance(body, dict) else body,
        }

    def ensure_collection(
        self,
        collection_name: str,
        text_vector_size: int = 768,
        clip_vector_size: int = 512,
        use_multivector: bool = False,
    ) -> None:
        """Ensure a collection exists, creating it if necessary.

        Args:
            collection_name: Name of the collection.
            text_vector_size: Dimension of the text embedding vector.
            clip_vector_size: Dimension of the CLIP embedding vector.
            use_multivector: If True, create a multi-vector collection with
                named vectors "text" and "clip". If False, create a single
                vector collection named "text".
        """
        if self._client.collection_exists(collection_name):
            logger.info(f"Collection '{collection_name}' already exists")
            return

        if use_multivector:
            vectors_config = {
                "text": VectorParams(size=text_vector_size, distance=Distance.COSINE),
                "clip": VectorParams(size=clip_vector_size, distance=Distance.COSINE),
            }
        else:
            vectors_config = {
                "text": VectorParams(size=text_vector_size, distance=Distance.COSINE),
            }

        self._client.create_collection(
            collection_name=collection_name,
            vectors_config=vectors_config,
        )
        logger.info(f"Created collection '{collection_name}' (multivector={use_multivector})")

    def create_collection(
        self,
        collection_name: str,
        vector_size: int = 768,
        distance: Distance = Distance.COSINE,
        vector_name: str = "text",
    ) -> None:
        """Create a new collection with a single named vector.

        Args:
            collection_name: Name of the collection.
            vector_size: Dimension of the embedding vector.
            distance: Distance metric (COSINE, DOT, EUCLID).
            vector_name: Name for the vector.
        """
        if self._client.collection_exists(collection_name):
            raise ValueError(f"Collection '{collection_name}' already exists")
        self._client.create_collection(
            collection_name=collection_name,
            vectors_config={vector_name: VectorParams(size=vector_size, distance=distance)},
        )
        logger.info(f"Created collection '{collection_name}' with vector '{vector_name}' (size={vector_size})")

    def upsert(self, collection_name: str, points: list[PointStruct]) -> None:
        """Batch upsert points into a collection.

        Args:
            collection_name: Target collection.
            points: List of PointStruct objects to upsert.
        """
        if not points:
            return
        self._client.upsert(collection_name=collection_name, points=points)

    def upsert_single(
        self,
        collection_name: str,
        point_id: int | str,
        vector: list[float] | dict[str, list[float]],
        payload: dict[str, Any],
    ) -> None:
        """Upsert a single point.

        Args:
            collection_name: Target collection.
            point_id: Point ID (int or UUID string).
            vector: Embedding vector (list for single vector, dict for named vectors).
            payload: Payload dict to store with the point.
        """
        point = PointStruct(id=point_id, vector=cast(Any, vector), payload=payload)
        self._client.upsert(collection_name=collection_name, points=[point])

    def set_payload(
        self,
        collection_name: str,
        point_id: int | str,
        payload: dict[str, Any],
    ) -> None:
        """Merge fields into an existing point's payload without touching its vectors.

        Used to write enrichment results back onto an already-ingested point
        (e.g. the auto-enrich playbook step) — a targeted payload patch rather
        than a full re-upsert, which would require re-supplying the vectors.

        Args:
            collection_name: Target collection.
            point_id: Point ID (int or UUID string) to update.
            payload: Fields to merge into the point's existing payload.
        """
        self._client.set_payload(
            collection_name=collection_name,
            payload=payload,
            points=[point_id],
        )

    def search(
        self,
        collection_name: str,
        query_vector: list[float],
        limit: int = 10,
        score_threshold: float = 0.0,
        using: Optional[str] = None,
        query_filter: Optional[Filter] = None,
        with_payload: bool = True,
        with_vectors: bool = False,
    ) -> list[Any]:
        """Search a collection for similar vectors.

        Args:
            collection_name: Collection to search.
            query_vector: Query embedding vector.
            limit: Maximum number of results.
            score_threshold: Minimum similarity score.
            using: Name of the vector to search (for multi-vector collections).
            query_filter: Optional Qdrant filter.
            with_payload: Include payload in results.
            with_vectors: Include vectors in results.

        Returns:
            List of ScoredPoint objects.
        """
        kwargs: dict[str, Any] = {
            "collection_name": collection_name,
            "query": query_vector,
            "limit": limit,
            "with_payload": with_payload,
            "with_vectors": with_vectors,
        }
        if score_threshold > 0:
            kwargs["score_threshold"] = score_threshold
        if using:
            kwargs["using"] = using
        if query_filter:
            kwargs["query_filter"] = query_filter
        response = self._client.query_points(**kwargs)
        return list(response.points)

    def find_similar_image_hash(
        self, collection_name: str, image_hash: str, max_distance: int, limit: int = 10_000
    ) -> Any | None:
        """Find an already-indexed perceptually similar image."""
        if not image_hash:
            return None
        points, _ = self.scroll(collection_name, limit=limit, with_payload=True, with_vectors=False)
        target = int(image_hash, 16)
        for point in points:
            candidate = (point.payload or {}).get("image_hash")
            if not candidate:
                continue
            try:
                if (target ^ int(candidate, 16)).bit_count() <= max_distance:
                    return point
            except ValueError:
                continue
        return None

    def search_named(
        self,
        collection_name: str,
        query_vector: list[float],
        vector_name: str = "text",
        limit: int = 10,
        score_threshold: float = 0.0,
        query_filter: Optional[Filter] = None,
    ) -> list[Any]:
        """Search using a specific named vector in a multi-vector collection.

        Args:
            collection_name: Collection to search.
            query_vector: Query embedding vector.
            vector_name: Name of the vector to search ("text" or "clip").
            limit: Maximum number of results.
            score_threshold: Minimum similarity score.
            query_filter: Optional Qdrant filter.

        Returns:
            List of ScoredPoint objects.
        """
        return self.search(
            collection_name=collection_name,
            query_vector=query_vector,
            limit=limit,
            score_threshold=score_threshold,
            using=vector_name,
            query_filter=query_filter,
        )

    def scroll(
        self,
        collection_name: str,
        limit: int = 100,
        offset: Optional[int | str] = None,
        with_payload: bool = True,
        with_vectors: bool = False,
        scroll_filter: Optional[Filter] = None,
    ) -> tuple[list[Any], Optional[int | str]]:
        """Scroll through points in a collection for pagination.

        Args:
            collection_name: Collection to scroll.
            limit: Number of points per page.
            offset: Offset for pagination (point ID or int).
            with_payload: Include payload in results.
            with_vectors: Include vectors in results.
            scroll_filter: Optional Qdrant filter.

        Returns:
            Tuple of (points, next_offset). next_offset is None when
            all points have been retrieved.
        """
        kwargs: dict[str, Any] = {
            "collection_name": collection_name,
            "limit": limit,
            "with_payload": with_payload,
            "with_vectors": with_vectors,
        }
        if offset is not None:
            kwargs["offset"] = offset
        if scroll_filter is not None:
            kwargs["scroll_filter"] = scroll_filter
        points, next_offset = self._client.scroll(**kwargs)
        if next_offset is not None and not isinstance(next_offset, (int, str)):
            next_offset = str(next_offset)
        return points, next_offset

    def get_point(self, collection_name: str, point_id: int | str) -> Optional[Any]:
        """Retrieve a single point by ID.

        Args:
            collection_name: Collection name.
            point_id: Point ID.

        Returns:
            Record object or None if not found.
        """
        try:
            results = self._client.retrieve(
                collection_name=collection_name,
                ids=[point_id],
                with_payload=True,
                with_vectors=True,
            )
            return results[0] if results else None
        except Exception as e:
            logger.error(f"Failed to get point {point_id} from {collection_name}: {e}")
            return None

    def delete_point(self, collection_name: str, point_id: int | str) -> None:
        """Delete a single point by ID.

        Args:
            collection_name: Collection name.
            point_id: Point ID to delete.
        """
        from qdrant_client.http.models import PointIdsList
        self._client.delete(
            collection_name=collection_name,
            points_selector=PointIdsList(points=[point_id]),
        )

    def delete_collection(self, collection_name: str) -> None:
        """Delete an entire collection.

        Args:
            collection_name: Name of the collection to delete.
        """
        self._client.delete_collection(collection_name=collection_name)
        logger.info(f"Deleted collection '{collection_name}'")

    def list_collections(self) -> list[dict[str, Any]]:
        """List all collections with point counts.

        Returns:
            List of dicts with collection_name, points_count, vector_config info.
        """
        collections = self._client.get_collections().collections
        result: list[dict[str, Any]] = []
        for col in collections:
            info: dict[str, Any] = {"name": col.name}
            try:
                col_info = self._client.get_collection(col.name)
                info["points_count"] = col_info.points_count or 0
                info["vectors_count"] = col_info.indexed_vectors_count or 0
                if col_info.config and col_info.config.params:
                    vectors_config = col_info.config.params.vectors
                    if vectors_config is not None and not isinstance(vectors_config, dict):
                        info["vector_size"] = vectors_config.size
                        info["vector_name"] = "default"
                        info["distance"] = str(vectors_config.distance)
                    elif isinstance(vectors_config, dict):
                        info["vectors"] = {
                            name: {"size": vc.size, "distance": str(vc.distance)}
                            for name, vc in vectors_config.items()
                        }
            except Exception as e:
                logger.warning(f"Failed to get info for collection '{col.name}': {e}")
                info["points_count"] = 0
            result.append(info)
        return result

    def get_collection_info(self, collection_name: str) -> Optional[dict[str, Any]]:
        """Get detailed info about a specific collection.

        Args:
            collection_name: Collection name.

        Returns:
            Dict with collection info or None if not found.
        """
        try:
            info = self._client.get_collection(collection_name)
            result: dict[str, Any] = {
                "name": collection_name,
                "points_count": info.points_count or 0,
                "vectors_count": info.indexed_vectors_count or 0,
                "status": str(info.status) if info.status else "unknown",
            }
            if info.config and info.config.params:
                vectors_config = info.config.params.vectors
                if vectors_config is not None and not isinstance(vectors_config, dict):
                    result["vector_size"] = vectors_config.size
                    result["vector_name"] = "default"
                    result["distance"] = str(vectors_config.distance)
                elif isinstance(vectors_config, dict):
                    result["vectors"] = {
                        name: {"size": vc.size, "distance": str(vc.distance)}
                        for name, vc in vectors_config.items()
                    }
            return result
        except Exception as e:
            logger.error(f"Failed to get collection info for '{collection_name}': {e}")
            return None

    def count_points(self, collection_name: str) -> int:
        """Count the number of points in a collection.

        Args:
            collection_name: Collection name.

        Returns:
            Point count, or 0 if the collection doesn't exist.
        """
        try:
            info = self._client.get_collection(collection_name)
            return info.points_count or 0
        except Exception:
            return 0

    def get_server_version(self) -> str:
        """Get the Qdrant server version.

        Returns:
            Version string or 'unknown'.
        """
        try:
            # QdrantClient doesn't have a direct version endpoint;
            # we can try to get it from the health check
            import httpx
            resp = httpx.get(f"http://{self._host}:{self._port}/", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("version", "unknown")
        except Exception as exc:
            logger.debug("Qdrant version probe unavailable: %s", type(exc).__name__)
        return "unknown"

    @staticmethod
    def stable_id(filepath: str, chunk_index: int = 0) -> int:
        """Generate a stable, collision-resistant point ID from filepath and chunk index.

        Uses SHA-256 hash of "filepath:chunk_index" truncated to 63 bits
        (Qdrant supports unsigned 64-bit integers, but we use 63 to be safe).

        Args:
            filepath: Source file path.
            chunk_index: Chunk index within the file.

        Returns:
            Integer point ID.
        """
        key = f"{filepath}:{chunk_index}"
        hash_hex = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return int(hash_hex[:15], 16)  # 60 bits, well within int64 range
