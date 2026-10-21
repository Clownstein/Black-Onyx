# Data and backup

## First administrator

After the first start, create the initial administrator:

```bash
black-onyx users bootstrap-admin --email admin@example.com
```

The command prompts for a password and refuses to run once any user exists. Every other account is created from an invitation issued under **Administration**.

The application creates its database schemas transactionally at startup; no manual schema step is needed.

## In-app continuity backup

Administrators can create consistent packages from **Administration → Continuity** or:

- `GET /api/v1/admin/backup` / `…/inventory` list known backups and state inventory
- `POST /api/v1/admin/backup/create` zip SQLite state + Qdrant snapshots
- `GET /api/v1/admin/backup/{backup_id}/download` download package
- `POST /api/v1/admin/backup/upload` import an external package
- `POST /api/v1/admin/backup/restore` restore a package (service may need restart afterward)
- `DELETE /api/v1/admin/backup/{backup_id}` delete a stored package

Prefer Continuity when both application state and vectors must stay aligned.

## Detection and TIP systems of record

Detection services live under `detection/`, `contracts/`, `packages/`, `services/`, and `web/`.

| Domain | System of record |
|---|---|
| Incidents / findings | Postgres (`incident_api`) |
| Cases (TIP notes/IOCs) | SQLite cases linked to incident ids |
| Assets | Postgres (`asset_registry`) |
| Threat intel match-on-wire | Postgres (`threat_intel`) + Kafka |
| TIP publish (MISP/TAXII) | Black Onyx publish path |
| TIP playbooks | Black Onyx `src/black_onyx/automation/` |
| SOAR approve/execute | Postgres (`response_orchestrator`) |
| Evidence / RAG / auth | SQLite + Qdrant (`all-knowledge-qwen3` or `all-knowledge`, `feed-*`, `web-search`; the Qwen3 profile uses **2560-dim** vectors, see [qwen3-embeddings.md](operations/qwen3-embeddings.md)) |
| Vector findings/incidents | Shared Qdrant (namespaced collections) |

### Threat intel write rules

- **Match-on-wire / feed ingest:** write only to Postgres `threat_intel` (+ Kafka consumers). Do not dual-write into TIP SQLite IOC stores.
- **Analyst publish (MISP/TAXII/export):** use Black Onyx publish routes; MISP publish also best-effort syncs IOCs into `threat_intel` via `POST …/api/v1/indicators/upsert`. Explicit sync: `POST /api/v1/threat-intel/sync-indicators`.
- **UI:** `/hunt` federates OpenSearch + detection vector search; `/search` remains TIP semantic search over Qdrant evidence (cross-linked).

### Assets

- **System of record:** Postgres `asset_registry`. Asset creation and CSV import write here only.
- **TIP SQLite:** holds posture-board and case-link helpers keyed by asset id; it is not a second inventory. Registry assets are mirrored into SQLite when a case link is created.

### Cases ↔ incidents

TIP cases store `external_incident_id` linking to Postgres `incident_api` incidents. Promote from Triage via `POST /api/v1/detection-incidents/promote`. Incident disposition/timeline remain in Postgres.

### Shared libraries

`packages/black_onyx_{contracts,otel,vector,calibration}` import as `black_onyx_*`. Docker builds install from `packages/`.

### Detection UI routes

`/detection`, `/incidents`, `/findings`, `/hunt`, `/malware`, `/attack-coverage`, `/models`, `/detection-services`, `/detection/metrics`, `/detection/network`, `/detection/code-changes`, `/data-health`, `/response-queue`, `/security-profiles` plus merges into existing `/assets`, `/attack`, `/admin`, `/triage`, `/cases`.

### Postgres databases

`incident_api`, `asset_registry`, `threat_intel`, `integration_hub`, `response_orchestrator`, `notification_service`, `training_orchestrator` (+ optional `smoke`).

### Infra

Root overlays:
- [`docker-compose.platform.yml`](../docker-compose.platform.yml) Redpanda, Postgres, OpenSearch, MinIO, Redis, MLflow on the **same Compose project network** as `web`/`qdrant` (do not force a separate network name).
- [`docker-compose.detection-core.yml`](../docker-compose.detection-core.yml) minimal ingest + smoke-consumer + incident-api + asset-registry.
- [`docker-compose.detection-apps.yml`](../docker-compose.detection-apps.yml) full detection service set (`deploy/detection/compose/docker-compose.apps.yml`).

**One Qdrant only** (existing `qdrant` service). Smoke: `pwsh scripts/smoke_detection_infra.ps1`.

### Human auth

Black Onyx session cookies. Detection APIs are reached via `/api/v1/detection/*` BFF with a short-lived JWT. Browser never holds service keys.

## Routine filesystem backup

Stop the service when possible, then back up the entire state directory and a Qdrant snapshot. For an online SQLite backup, use SQLite's backup API; copying only the main file may omit data that has not yet been checkpointed from the WAL.

Restore application state and Qdrant from the same recovery point. Verify authentication, job history, collection counts, case/watchlist contents, triage queues, connectors, and chat ownership before returning the instance to service.
