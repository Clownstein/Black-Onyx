"""Thin Qdrant client wrapper with mandatory tenant filtering.

The wrapper is intentionally small and dependency-tolerant:

* ``qdrant-client`` is a soft import. If it is not installed the wrapper can
  still be constructed with an injected client (used by unit tests with a mock)
  and its ``tenant_filter`` / point helpers keep working with plain dicts.
* Every search/recommend call requires a ``tenant_id`` and always injects a
  ``tenant_id`` payload filter — tenant scoping is enforced in application code,
  not only by convention (see ``qdrant_implementation.md`` §9.2).
"""

from __future__ import annotations

import logging
from typing import Any

from black_onyx_vector.collections import (
    COLLECTIONS,
    GLOBAL_TENANT,
    CollectionSpec,
)

logger = logging.getLogger(__name__)

try:  # soft import: qdrant-client is optional at import time
    from qdrant_client import QdrantClient
    from qdrant_client import models as qmodels

    _HAS_QDRANT = True
except Exception:  # noqa: BLE001 - any import failure means "not available"
    QdrantClient = None  # type: ignore[assignment]
    qmodels = None  # type: ignore[assignment]
    _HAS_QDRANT = False


def has_qdrant() -> bool:
    """Return True when the ``qdrant-client`` library is importable."""

    return _HAS_QDRANT


class VectorClient:
    """Tenant-aware wrapper around a Qdrant client.

    Parameters
    ----------
    url:
        Qdrant HTTP URL (e.g. ``http://localhost:6333``). Ignored when ``client``
        is supplied.
    api_key:
        Optional Qdrant API key.
    client:
        Pre-built client (or mock). When omitted a real ``QdrantClient`` is
        created if ``qdrant-client`` is installed and ``url`` is set.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        api_key: str | None = None,
        client: Any | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.url = url
        if client is not None:
            self._client = client
        elif _HAS_QDRANT and url:
            self._client = QdrantClient(url=url, api_key=api_key or None, timeout=timeout)
        else:
            self._client = None

    @property
    def available(self) -> bool:
        """True when an underlying client is present (real or injected)."""

        return self._client is not None

    @property
    def raw(self) -> Any:
        """The underlying Qdrant client (or None)."""

        return self._client

    # ------------------------------------------------------------------ filters
    @staticmethod
    def tenant_filter(
        tenant_id: str,
        *,
        extra_must: list[dict[str, Any]] | None = None,
        include_global: bool = False,
    ) -> dict[str, Any]:
        """Build a payload filter that always constrains ``tenant_id``.

        When ``include_global`` is set, points tagged with the shared
        ``__global__`` tenant are also matched (used for feed intel / ATT&CK /
        platform runbooks).
        """

        if not tenant_id:
            raise ValueError("tenant_id is required for tenant-scoped vector search")
        conditions = list(extra_must or [])
        if include_global:
            return {
                "must": conditions,
                "should": [
                    {"key": "tenant_id", "match": {"value": tenant_id}},
                    {"key": "tenant_id", "match": {"value": GLOBAL_TENANT}},
                ],
            }
        return {"must": [{"key": "tenant_id", "match": {"value": tenant_id}}, *conditions]}

    @staticmethod
    def _to_qdrant_filter(flt: Any) -> Any:
        if flt is None or not _HAS_QDRANT:
            return flt
        if isinstance(flt, qmodels.Filter):
            return flt

        def _cond(cond: dict[str, Any]) -> Any:
            key = cond["key"]
            if "match" in cond:
                return qmodels.FieldCondition(
                    key=key, match=qmodels.MatchValue(value=cond["match"]["value"])
                )
            if "range" in cond:
                return qmodels.FieldCondition(key=key, range=qmodels.Range(**cond["range"]))
            return qmodels.FieldCondition(key=key)

        kwargs: dict[str, Any] = {}
        for section in ("must", "should", "must_not"):
            items = flt.get(section)
            if items:
                kwargs[section] = [_cond(c) for c in items]
        return qmodels.Filter(**kwargs)

    # ------------------------------------------------------------- provisioning
    def ensure_collections(self, names: list[str] | None = None) -> list[str]:
        """Create any missing collections (and payload indexes) idempotently.

        Returns the list of collection names that were created.
        """

        if self._client is None:
            raise RuntimeError("vector client is not available")
        selected = names or list(COLLECTIONS.keys())
        created: list[str] = []
        for name in selected:
            spec = COLLECTIONS[name]
            if self._collection_exists(name):
                continue
            self._client.create_collection(
                collection_name=name,
                vectors_config=self._vectors_config(spec),
                sparse_vectors_config=self._sparse_config(spec),
            )
            created.append(name)
            self._ensure_payload_indexes(spec)
        return created

    def _collection_exists(self, name: str) -> bool:
        exists = getattr(self._client, "collection_exists", None)
        if callable(exists):
            try:
                return bool(exists(name))
            except Exception:  # noqa: BLE001
                return False
        return False

    def _vectors_config(self, spec: CollectionSpec) -> Any:
        if not _HAS_QDRANT:
            return {
                vname: {"size": size, "distance": spec.distance}
                for vname, size in spec.vectors.items()
            }
        distance = getattr(qmodels.Distance, spec.distance.upper(), qmodels.Distance.COSINE)
        return {
            vname: qmodels.VectorParams(size=size, distance=distance)
            for vname, size in spec.vectors.items()
        }

    def _sparse_config(self, spec: CollectionSpec) -> Any:
        if not spec.sparse:
            return None
        if not _HAS_QDRANT:
            return {"sparse": {}}
        return {"sparse": qmodels.SparseVectorParams()}

    def _ensure_payload_indexes(self, spec: CollectionSpec) -> None:
        create_index = getattr(self._client, "create_payload_index", None)
        if not callable(create_index):
            return
        schema_map: list[tuple[tuple[str, ...], str]] = [
            (spec.keyword_indexes, "keyword"),
            (spec.integer_indexes, "integer"),
            (spec.float_indexes, "float"),
            (spec.bool_indexes, "bool"),
        ]
        for fields, schema in schema_map:
            for field_name in fields:
                try:
                    create_index(
                        collection_name=spec.name,
                        field_name=field_name,
                        field_schema=schema,
                    )
                except Exception:  # noqa: BLE001 - index creation is best-effort
                    logger.debug("payload index create failed: %s.%s", spec.name, field_name)

    # -------------------------------------------------------------------- writes
    def _to_point(self, point: Any) -> Any:
        if not _HAS_QDRANT:
            return point
        if isinstance(point, qmodels.PointStruct):
            return point
        return qmodels.PointStruct(
            id=point["id"],
            vector=point["vector"],
            payload=point.get("payload"),
        )

    def upsert(
        self,
        collection: str,
        points: list[dict[str, Any]],
        *,
        wait: bool = True,
    ) -> Any:
        """Upsert points. Each point is ``{id, vector, payload}``.

        ``vector`` may be a mapping of named vectors (``{"dense": [...]}``) or a
        bare list. Points missing ``tenant_id`` in their payload are rejected at
        the application layer for tenant-scoped collections.
        """

        if self._client is None:
            raise RuntimeError("vector client is not available")
        spec = COLLECTIONS.get(collection)
        tenant_scoped = bool(spec) and "tenant_id" in (spec.keyword_indexes if spec else ())
        prepared: list[Any] = []
        for point in points:
            payload = point.get("payload") or {}
            if tenant_scoped and not payload.get("tenant_id"):
                raise ValueError(
                    f"payload for collection {collection} must set tenant_id "
                    f"(use '{GLOBAL_TENANT}' for shared data)"
                )
            prepared.append(self._to_point(point))
        return self._client.upsert(collection_name=collection, points=prepared, wait=wait)

    # ------------------------------------------------------------------- reads
    @staticmethod
    def _normalize_hit(hit: Any) -> dict[str, Any]:
        if isinstance(hit, dict):
            return {
                "id": hit.get("id"),
                "score": hit.get("score"),
                "payload": hit.get("payload"),
            }
        return {
            "id": getattr(hit, "id", None),
            "score": getattr(hit, "score", None),
            "payload": getattr(hit, "payload", None),
        }

    def search(
        self,
        collection: str,
        vector: list[float],
        tenant_id: str,
        *,
        vector_name: str = "dense",
        limit: int = 10,
        include_global: bool = False,
        extra_must: list[dict[str, Any]] | None = None,
        with_payload: bool = True,
    ) -> list[dict[str, Any]]:
        """Nearest-neighbor search with a mandatory tenant filter."""

        if self._client is None:
            raise RuntimeError("vector client is not available")
        flt = self.tenant_filter(
            tenant_id, extra_must=extra_must, include_global=include_global
        )
        hits = self._client.search(
            collection_name=collection,
            query_vector=(vector_name, vector),
            query_filter=self._to_qdrant_filter(flt),
            limit=limit,
            with_payload=with_payload,
        )
        return [self._normalize_hit(h) for h in (hits or [])]

    def recommend(
        self,
        collection: str,
        positive_ids: list[str],
        tenant_id: str,
        *,
        vector_name: str = "dense",
        limit: int = 10,
        include_global: bool = False,
        extra_must: list[dict[str, Any]] | None = None,
        with_payload: bool = True,
    ) -> list[dict[str, Any]]:
        """Recommend points similar to already-stored points (by id).

        Used for "find similar to this finding/incident" without re-embedding.
        """

        if self._client is None:
            raise RuntimeError("vector client is not available")
        flt = self.tenant_filter(
            tenant_id, extra_must=extra_must, include_global=include_global
        )
        hits = self._client.recommend(
            collection_name=collection,
            positive=positive_ids,
            using=vector_name,
            query_filter=self._to_qdrant_filter(flt),
            limit=limit,
            with_payload=with_payload,
        )
        return [self._normalize_hit(h) for h in (hits or [])]


__all__ = ["VectorClient", "has_qdrant"]
