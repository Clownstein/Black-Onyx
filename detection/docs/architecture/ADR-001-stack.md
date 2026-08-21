# ADR-001: Phase 0 technology stack

## Status

Accepted (Phase 0)

## Context

The Anomaly Detection Platform needs a local foundation that can ingest telemetry, persist assets and events, and expose health/metrics before modality-specific models land. Stack choices must support async fail-open ingestion, multi-tenant isolation, and later ONNX/MLflow serving.

## Decision

| Concern | Choice | Rationale |
| --- | --- | --- |
| Event broker | Redpanda (Kafka API) | Kafka-compatible, single-binary local ops, topics for raw/DLQ streams |
| Primary store | PostgreSQL 16 | Relational assets, incidents, idempotent event upserts |
| Search (later) | OpenSearch | Finding/incident full-text and timeline queries |
| Object store | MinIO (S3 API) | Model artifacts, raw blobs, training datasets |
| Cache / locks | Redis | Rate limits, short-lived coordination |
| Experiment tracking | MLflow | Model registry and training runs (Phase 1+) |
| Ingestion gateway | Go + segmentio/kafka-go | Low-latency HTTP ingest, strict validation, metrics |
| Control-plane APIs | Python 3.12+ FastAPI | Asset registry, incident API, ML adjacency |
| Contracts | JSON Schema + Pydantic + Go structs | Shared envelope across languages |
| Local orchestration | Docker Compose | Reproducible Phase 0 developer environment |

## Consequences

- All services speak Kafka protocol for Redpanda; topic names are versioned (`logs.raw`, `logs.raw.dlq`).
- Tenant isolation in Phase 0 uses `X-Tenant-Id` (or OIDC stub claims later); every persisted row includes `tenant_id`.
- Compose uses reduced retention for Redpanda/OpenSearch so laptops stay usable.
- Go toolchain is required to build `ingestion-gateway`; CI builds it even if a developer machine lacks Go locally.
- Optional vector search (Qdrant) is documented in **[ADR-002](ADR-002-vector-qdrant.md)** and does not change Phase 0 defaults.

## Alternatives considered

- **Apache Kafka full cluster** — heavier local footprint than Redpanda for Phase 0.
- **RabbitMQ** — weaker multi-consumer log replay semantics for telemetry.
- **gRPC-only ingest** — deferred; HTTP batch ingest is simpler for collectors and smoke tests.
