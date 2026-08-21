# ADR-002: Optional Qdrant vector search plane

## Status

Accepted (Phase 6)

## Context

Analysts and correlation need “find similar” and semantic threat-intel retrieval beyond Postgres exact IOC match and OpenSearch full-text. Design notes in `docs_implemented/qdrant_implementation.md` proposed Qdrant as a complementary vector store. Postgres remains the system of record; OpenSearch remains the hunt/full-text plane.

## Decision

| Concern | Choice |
| --- | --- |
| Vector DB | **Qdrant** (Compose service `qdrant`, profile **`vector`**) |
| Shared client | `packages/black_onyx_vector` — tenant-filtered search, collection specs |
| Dense dim / distance | **768** Cosine (SecureBERT 2.0 bi-encoder) |
| Collections | `findings_v1`, `incidents_v1`, `features_baseline_v1`, `ti_text_v1`, `attack_tech_v1`, `runbooks_v1` |
| Embedding pipeline | `services/embedding-worker` (Kafka optional; off by default in Compose) |
| Feature flags | `VECTOR_SEARCH_ENABLED`, `FEDERATED_HUNT_ENABLED`, `VECTOR_NOVELTY_ENABLED` default **false** |
| Soft-fail | Missing Qdrant must not break golden ingest → finding → incident path |
| Tenant isolation | Payload filter on `tenant_id`; shared CTI/ATT&CK may use `__global__` |

## Consequences

- Local enablement requires `--profile vector` plus explicit env flags (see `docs/operations/qdrant-vector-search.md`).
- The Helm chart includes `embedding-worker` but does not bundle Qdrant or model
  artifacts. Operators must provide a resolvable Qdrant service and reviewed embedding
  artifacts; chart rendering alone is not vector-runtime proof.
- Semantic TI and vector novelty are **advisory** signals; SOAR must not auto-execute on vector-only evidence.
- ADR-001 remains the Phase 0 stack; this ADR adds an optional layer without superseding OpenSearch or Postgres.

## Alternatives considered

- **pgvector in PostgreSQL** — couples ANN load to the SoR; deferred.
- **OpenSearch k-NN only** — viable later; Qdrant chosen for dedicated ANN ops and named/multi-vector collections (`features_baseline_v1`).
- **Bundled substitute embeddings** — rejected; unit tests inject a test-only model, while production fails closed if the configured model is unavailable.
