# ADR-001: Detection platform technology stack

## Status

Accepted

## Context

The detection platform needs a stack for telemetry ingestion, asset and incident persistence, model services, and operational health. The selected components support asynchronous ingestion, tenant isolation, and independently deployed model services.

## Decision

| Concern | Choice | Rationale |
| --- | --- | --- |
| Event broker | Redpanda (Kafka API) | Kafka-compatible, single-binary local ops, topics for raw/DLQ streams |
| Primary store | PostgreSQL 16 | Relational assets, incidents, idempotent event upserts |
| Search | OpenSearch | Finding/incident full-text and timeline queries |
| Object store | MinIO (S3 API) | Model artifacts, raw blobs, training datasets |
| Cache / locks | Redis | Rate limits, short-lived coordination |
| Experiment tracking | MLflow | Model experiment tracking where configured |
| Ingestion gateway | Go + segmentio/kafka-go | Low-latency HTTP ingest, strict validation, metrics |
| Control-plane APIs | Python 3.12+ FastAPI | Asset registry, incident API, ML adjacency |
| Contracts | JSON Schema + Pydantic + Go structs | Shared envelope across languages |
| Local orchestration | Docker Compose | Reproducible development and integration environments |

## Consequences

- All services speak Kafka protocol for Redpanda; topic names are versioned (`logs.raw`, `logs.raw.dlq`).
- Tenant identity is validated at service boundaries and persisted as `tenant_id` on tenant-scoped records.
- Compose uses reduced retention for Redpanda/OpenSearch so laptops stay usable.
- Go toolchain is required to build `ingestion-gateway`; CI builds it even if a developer machine lacks Go locally.
- Shared Qdrant vector search is documented in **[ADR-002](ADR-002-vector-qdrant.md)** and is enabled through explicit feature configuration.

## Alternatives considered

- **Apache Kafka full cluster:** higher local resource requirements than Redpanda.
- **RabbitMQ:** weaker multi-consumer log replay semantics for telemetry.
- **gRPC-only ingest:** not selected; HTTP batch ingest serves collectors and integration workflows.
