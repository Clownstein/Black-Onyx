# Detection platform

Black Onyx includes a Kafka/Postgres detection plane. This page describes
service ownership, data flow, and what you must configure.

## Systems of record

| Data | System of record | Notes |
| --- | --- | --- |
| Threat intelligence, evidence, cases, and application state | TIP SQLite | Qdrant provides shared vector search and evidence retrieval. |
| Incidents and findings | `incident-api` Postgres | Browser clients access detection operations through the TIP BFF. |
| Assets | `asset-registry` Postgres | All asset creates and updates go through the registry. |
| Detection events and model outputs | Kafka topics and detection services | Services validate contracts and persist incident state through their owning APIs. |

## User workflows

The web application provides detection overview, incidents, findings, hunt,
malware, attack coverage, model operations, service health, metrics, network
and code-change views, assets, data health, response queue, security profiles,
and administration. The classic shell and Gallery hub share the same
authenticated application and API.

Triage links TIP cases to detection incidents using the external incident ID.
Disposition and acknowledgement updates are written through the detection BFF
to the incident system of record.

## Detection data flow

Collectors and ingestion services validate events against shared contracts.
Kafka carries normalized telemetry to modality processors and inference
workers. The incident API owns findings and incidents; the asset registry
owns assets. Shared Qdrant supports semantic retrieval and vector hunt when
those features are enabled.

The platform includes log, network, metrics, code, malware-static, and
host-state paths. Host-state analysis is rules-based and inference-only. The
cloud flow collectors support AWS VPC Flow Logs, Azure NSG Flow Logs, and GCP
VPC Flow Logs. Kubernetes CNI/eBPF telemetry is outside the supported collector
set.

## Identity and mutation policy

- Human access uses session cookies, CSRF protection, and `admin`, `analyst`,
  and `viewer` roles.
- Browser detection requests use `/api/v1/detection/*`. The BFF mints
  detection-service tokens and forwards only declared, schema-validated
  operations. Browser-held service keys and detection JWTs are not used.
- MCP services authenticate with `X-MCP-Service-Key` and a configured actor
  user ID. MCP processes do not use browser cookies.
- Consequential response actions begin in preview and require server-side
  approval. Model-supplied confirmation values do not authorize execution.
- Security tools use signed actor assertions, structured arguments, sandbox
  image capability checks, and single-use approvals for non-read actions.

## Model lifecycle

Supported training modalities use durable Postgres-backed jobs and signed
artifacts. Reviewed datasets are required for operational training; synthetic
datasets require explicit lab configuration and remain labeled. Serving
replicas verify and load packages before a model alias is promoted. Host-state
has no trained package and remains inference-only.

## Notifications and external services

The notification outbox records delivery attempts and retries. Without a
configured provider, an event is marked `logged-only`, not `sent`. Malware
detonation, GPU inference, SMTP/webhook delivery, and other external services
require their corresponding operator-managed systems and credentials.

## Deployment profiles

- Root Compose provides the TIP application and shared Qdrant; platform and
  detection overlays add Kafka/Postgres services and consumers.
- Lab overlays expose selected loopback ports and may enable explicitly
  isolated development settings. Production defaults retain authentication,
  tenant isolation, and internal service networking.
- Helm templates include detection services, migrations, secrets, storage,
  model-serving configuration, and network policies. Supply environment-specific
  dependencies and validate the chart against the target cluster before
  rollout.
- Network-dependent security tools remain unavailable. A Docker network name,
  DNS validation, or host pinning does not provide per-job destination
  enforcement; the runner rejects non-offline jobs.

## Validation

Repository tests cover TIP and BFF behavior, service contracts, authorization,
Compose rendering, and Helm templates. Deployment-specific acceptance should
also exercise the configured identity provider, external notification and
response integrations, model hardware, backup scale, and cluster policies in
the intended environment. See [Development](DEVELOPMENT.md),
[Deployment](DEPLOYMENT.md), and [Security tools](SECURITY_TOOLS.md) for
operational procedures.
