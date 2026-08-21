"""Qdrant collection definitions for Black Onyx vector search.

These mirror the collection design in ``qdrant_implementation.md`` §5. Dense text
vectors are 768-dimensional (SecureBERT 2.0 bi-encoder) with Cosine distance and
are L2-normalized before upsert. ``features_baseline_v1`` uses modality-specific
named numeric vectors instead of a single dense text vector.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DENSE_SIZE = 768
DENSE_DISTANCE = "Cosine"
GLOBAL_TENANT = "__global__"
EMBED_MODEL_DEFAULT = "cisco-ai/SecureBERT2.0-biencoder"
EMBED_VERSION_DEFAULT = "1"


@dataclass(frozen=True)
class CollectionSpec:
    """Definition of a Qdrant collection: named vectors, sparse flag, indexes."""

    name: str
    vectors: dict[str, int]
    distance: str = DENSE_DISTANCE
    sparse: bool = False
    keyword_indexes: tuple[str, ...] = field(default_factory=tuple)
    integer_indexes: tuple[str, ...] = field(default_factory=tuple)
    float_indexes: tuple[str, ...] = field(default_factory=tuple)
    bool_indexes: tuple[str, ...] = field(default_factory=tuple)


COLLECTIONS: dict[str, CollectionSpec] = {
    "findings_v1": CollectionSpec(
        name="findings_v1",
        vectors={"dense": DENSE_SIZE},
        sparse=True,
        keyword_indexes=(
            "tenant_id",
            "finding_type",
            "modality",
            "asset_id",
            "incident_id",
            "mitre_techniques",
        ),
        integer_indexes=("occurred_at_ts",),
        float_indexes=("calibrated_score",),
    ),
    "incidents_v1": CollectionSpec(
        name="incidents_v1",
        vectors={"dense": DENSE_SIZE},
        sparse=True,
        keyword_indexes=("tenant_id", "status", "severity", "mitre_techniques"),
        integer_indexes=("created_at_ts",),
        float_indexes=("risk_score",),
    ),
    "features_baseline_v1": CollectionSpec(
        name="features_baseline_v1",
        vectors={
            "log": 128,
            "network": 64,
            "metrics": 64,
            "code": DENSE_SIZE,
            "host_state": 128,
        },
        sparse=False,
        keyword_indexes=("tenant_id", "modality", "asset_id", "service_id"),
        integer_indexes=("window_start_ts",),
        bool_indexes=("is_baseline",),
    ),
    "ti_text_v1": CollectionSpec(
        name="ti_text_v1",
        vectors={"dense": DENSE_SIZE},
        sparse=True,
        keyword_indexes=(
            "tenant_id",
            "observable_type",
            "source",
            "tlp",
            "campaigns",
            "mitre_techniques",
            "chunk_kind",
        ),
        integer_indexes=("valid_until_ts",),
        float_indexes=("confidence",),
    ),
    "attack_tech_v1": CollectionSpec(
        name="attack_tech_v1",
        vectors={"dense": DENSE_SIZE},
        sparse=False,
        keyword_indexes=("technique_id", "domain", "tactics"),
        bool_indexes=("is_subtechnique",),
    ),
    "runbooks_v1": CollectionSpec(
        name="runbooks_v1",
        vectors={"dense": DENSE_SIZE},
        sparse=True,
        keyword_indexes=("tenant_id", "doc_type", "tags", "mitre_techniques", "doc_id"),
    ),
}

COLLECTION_NAMES: tuple[str, ...] = tuple(COLLECTIONS.keys())
