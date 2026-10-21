# ADR-002: Optional Qdrant vector search plane

## Status

Accepted

## Context

Analysts and correlation need “find similar” and semantic threat-intel retrieval beyond Postgres exact IOC match and OpenSearch full-text. Qdrant is complementary to Postgres and OpenSearch (see [qdrant-vector-search.md](../operations/qdrant-vector-search.md)).

## Decision

| Concern | Choice |
| --- | --- |
| Vector DB | **Qdrant** (Compose service `qdrant`, profile **`vector`**) |
| Shared client | `packages/black_onyx_vector`: tenant-filtered search, collection specs |
| Dense dim / distance | **768** Cosine (SecureBERT 2.0 bi-encoder) |
| Collections | `findings_v1`, `incidents_v1`, `features_baseline_v1`, `ti_text_v1`, `attack_tech_v1`, `runbooks_v1` |
| Embedding pipeline | `services/embedding-worker` (Kafka optional; off by default in Compose) |
| Feature flags | `VECTOR_SEARCH_ENABLED`, `FEDERATED_HUNT_ENABLED`, `VECTOR_NOVELTY_ENABLED` default **false** |
| Soft-fail | Missing Qdrant must not break golden ingest → finding → incident path |
| Tenant isolation | Payload filter on `tenant_id`; shared CTI/ATT&CK may use `__global__` |

## Consequences

- Local enablement uses `--profile vector` plus env flags ([qdrant-vector-search.md](../operations/qdrant-vector-search.md)).
- The Helm chart includes `embedding-worker` but does not bundle Qdrant or model
  artifacts. Configure a resolvable Qdrant service and provide the reviewed embedding
  artifacts required by the selected model.
- Semantic TI and vector novelty are **advisory** signals; SOAR must not auto-execute on vector-only evidence.
- Qdrant complements OpenSearch and Postgres; it does not replace either system of record or search plane.

## Alternatives considered

- **pgvector in PostgreSQL:** couples ANN load to the system of record; not selected.
- **OpenSearch k-NN only:** viable later; Qdrant chosen for dedicated ANN ops and named/multi-vector collections (`features_baseline_v1`).
- **Bundled substitute embeddings:** rejected; unit tests inject a test-only model, while production fails closed if the configured model is unavailable.
