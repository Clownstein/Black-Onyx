"""Shared Qdrant vector-search helpers for Black Onyx detection.

Public surface:

* :class:`VectorClient` — tenant-aware wrapper (ensure collections, upsert,
  search, recommend, and a ``tenant_filter`` helper).
* Collection definitions and constants from :mod:`black_onyx_vector.collections`.
"""

from __future__ import annotations

from black_onyx_vector.client import VectorClient, has_qdrant
from black_onyx_vector.collections import (
    COLLECTION_NAMES,
    COLLECTIONS,
    DENSE_DISTANCE,
    DENSE_SIZE,
    EMBED_MODEL_DEFAULT,
    EMBED_VERSION_DEFAULT,
    GLOBAL_TENANT,
    CollectionSpec,
)

__version__ = "0.1.0"

__all__ = [
    "VectorClient",
    "has_qdrant",
    "CollectionSpec",
    "COLLECTIONS",
    "COLLECTION_NAMES",
    "DENSE_SIZE",
    "DENSE_DISTANCE",
    "GLOBAL_TENANT",
    "EMBED_MODEL_DEFAULT",
    "EMBED_VERSION_DEFAULT",
    "__version__",
]
