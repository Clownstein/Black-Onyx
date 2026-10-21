# Detection operations

Operator docs for the Black Onyx detection plane. Product architecture:
[docs/DETECTION_PLATFORM.md](../../docs/DETECTION_PLATFORM.md). Compose and tests:
[docs/DEVELOPMENT.md](../../docs/DEVELOPMENT.md).

## Architecture

| Document | Contents |
| --- | --- |
| [architecture/ADR-001-stack.md](architecture/ADR-001-stack.md) | Redpanda, Postgres, OpenSearch, MinIO, Redis |
| [architecture/ADR-002-vector-qdrant.md](architecture/ADR-002-vector-qdrant.md) | Optional Qdrant vector plane |

## Deployment

| Document | Contents |
| --- | --- |
| [deployment/cross-platform-agents.md](deployment/cross-platform-agents.md) | osquery, Vector, Wazuh shipper |
| [deployment/sysmon.md](deployment/sysmon.md) | Windows Sysmon → host-state |
| [deployment/velociraptor.md](deployment/velociraptor.md) | Velociraptor integration |
| [deployment/network-sensors.md](deployment/network-sensors.md) | Zeek, Suricata, cloud flow logs |
| [deployment/malware-lab.md](deployment/malware-lab.md) | CAPEv2 / DRAKVUF / lab stub |
| [deployment/multi-site.md](deployment/multi-site.md) | `site_id` tagging |

## Operations

| Document | Contents |
| --- | --- |
| [operations/opensearch-hunt.md](operations/opensearch-hunt.md) | Hunt indexes and federated hunt |
| [operations/qdrant-vector-search.md](operations/qdrant-vector-search.md) | Vector flags and collections |
| [operations/security-profiles.md](operations/security-profiles.md) | Framework packs and coverage |
| [operations/response-orchestrator.md](operations/response-orchestrator.md) | SOAR queue |
| [operations/hardening.md](operations/hardening.md) | Service hardening |
| [operations/slo.md](operations/slo.md) | Latency and availability targets |
| [operations/grafana-assistants.md](operations/grafana-assistants.md) | Grafana |
| [operations/otel-app-instrumentation.md](operations/otel-app-instrumentation.md) | OpenTelemetry |
| [operations/broker-outage.md](operations/broker-outage.md) | Redpanda outage |
| [operations/postgres-restore.md](operations/postgres-restore.md) | Postgres restore |
| [operations/model-rollback.md](operations/model-rollback.md) | Scorer rollback |

## Runbooks

| Document | Contents |
| --- | --- |
| [operations/runbooks/isolate-host.md](operations/runbooks/isolate-host.md) | Host isolation |
| [operations/runbooks/ti-enrich.md](operations/runbooks/ti-enrich.md) | Threat-intel enrich |
| [operations/runbooks/credential-reset.md](operations/runbooks/credential-reset.md) | Credential reset |

## Analyst assist

| Document | Contents |
| --- | --- |
| [defender/llm-investigation.md](defender/llm-investigation.md) | Investigation drafts (suggest-only) |
| [defender/mitre-coverage.md](defender/mitre-coverage.md) | ATT&CK coverage |
| [defender/purple-team.md](defender/purple-team.md) | Purple-team helpers |
