# State migration and backup

## First secured startup

Run `black-onyx users bootstrap-admin`. Before assigning legacy ownerless chat sessions, Black Onyx:

1. opens every legacy SQLite store through SQLite's backup API;
2. writes timestamped copies under `storage.state_dir/legacy-backups`;
3. verifies each backup with `PRAGMA integrity_check`;
4. migrates a staged chat database and assigns ownerless sessions to the new administrator;
5. verifies the staged database and atomically replaces the live chat store;
6. records `legacy-state-v1` in the canonical state database.

If verification fails, administrator creation is rolled back. The verified backups are retained. Re-running the migration is idempotent.

## Rename from DefenderChat / Defenders Chat

Product and package identifiers are now **Black Onyx**:

| Legacy | Current |
|---|---|
| Python package `defenders_chat` | `black_onyx` |
| CLI `defenders-chat` / `defenders-chat-web` | `black-onyx` / `black-onyx-web` |
| Env `DEFENDERS_CHAT_AUTH_SECRET` | `BLACK_ONYX_AUTH_SECRET` (legacy name still accepted) |
| Env `DEFENDERS_CHAT_PORT` | `BLACK_ONYX_PORT` |
| Cookies `defenderchat_*` | `blackonyx_session` / `blackonyx_csrf` |
| State DB `defenders_chat.sqlite` | `black_onyx.sqlite` (auto-adopted when the new DB has no users) |
| Docker image / user | `black-onyx` / `blackonyx` |
| Docker volumes | keep existing `defenderchat_*` names so model/Qdrant data is not orphaned |

After upgrading code, synchronize the workspace (`uv sync` with the required extras) or rebuild the Docker image so the root package and `black-onyx-contracts` resolve together. Browsers will receive new cookie names—users simply sign in again.

If login fails with “Invalid credentials” after a rename rebuild, check that Compose is using the real `BLACK_ONYX_AUTH_SECRET` from `.env` (a shell-exported test secret overrides `.env`) and that `black_onyx.sqlite` contains your users (or still has a populated `defenders_chat.sqlite` for adoption).

## In-app continuity backup

Administrators can create consistent packages from **Administration → Continuity** or:

- `GET /api/v1/admin/backup` / `…/inventory` — list known backups and state inventory
- `POST /api/v1/admin/backup/create` — zip SQLite state + Qdrant snapshots
- `GET /api/v1/admin/backup/{backup_id}/download` — download package
- `POST /api/v1/admin/backup/upload` — import an external package
- `POST /api/v1/admin/backup/restore` — restore a package (service may need restart afterward)
- `DELETE /api/v1/admin/backup/{backup_id}` — delete a stored package

Prefer Continuity when both application state and vectors must stay aligned.

## Black Onyx ↔ AutoAnalyzer absorption

AutoAnalyzer (anomaly detection spine) is absorbed into Black Onyx. Ported code lives under `detection/`, `contracts/`, `packages/`, `services/`, and `web/`. **Delete-after-port:** once a slice is verified in Black Onyx paths, the corresponding `AutoAnalyzer/` files are removed. End state: no `AutoAnalyzer/` tree.

### System of record

| Domain | SoR after merge |
|---|---|
| Incidents / findings | Postgres (`incident_api`) |
| Cases (TIP notes/IOCs) | SQLite cases linked to incident ids |
| Assets | Postgres (`asset_registry`); SQLite assets migrated then retired |
| Threat intel match-on-wire | Postgres (`threat_intel`) + Kafka |
| TIP publish (MISP/TAXII) | Black Onyx publish path |
| TIP playbooks | Black Onyx `src/black_onyx/automation/` |
| SOAR approve/execute | Postgres (`response_orchestrator`) |
| Evidence / RAG / auth | SQLite + Qdrant (`all-knowledge`, `feed-*`, `detect-*`) |
| Vector findings/incidents | Shared Qdrant (namespaced collections) |

### Threat intel write rules

- **Match-on-wire / feed ingest:** write only to Postgres `threat_intel` (+ Kafka consumers). Do not dual-write into TIP SQLite IOC stores.
- **Analyst publish (MISP/TAXII/export):** use Black Onyx publish routes; MISP publish also best-effort syncs IOCs into `threat_intel` via `POST …/api/v1/indicators/upsert`. Explicit sync: `POST /api/v1/threat-intel/sync-indicators`.
- **UI:** `/hunt` federates OpenSearch + detection vector search; `/search` remains TIP semantic search over Qdrant evidence (cross-linked).

### Assets cutover

- **SoR:** Postgres `asset_registry`. Create and CSV import write here only.
- **One-way migrate:** `POST /api/v1/assets/migrate` copies remaining TIP SQLite inventory into the registry.
- **TIP SQLite:** kept only for posture board / case-link helpers keyed by asset id; not a second inventory write path. Registry-only assets are mirrored into SQLite when a case link is created.

### Cases ↔ incidents

TIP cases store `external_incident_id` linking to Postgres `incident_api` incidents. Promote from Triage via `POST /api/v1/detection-incidents/promote`. Incident disposition/timeline remain in Postgres.

### Shared libraries

`packages/black_onyx_{contracts,otel,vector,calibration}` — import as `black_onyx_*`. Docker builds install from `packages/`. There is no `AutoAnalyzer/` tree.

### UI routes ported into `web/`

`/detection`, `/incidents`, `/findings`, `/hunt`, `/malware`, `/attack-coverage`, `/models`, `/detection-services`, `/detection/metrics`, `/detection/network`, `/detection/code-changes`, `/data-health`, `/response-queue`, `/security-profiles` — plus merges into existing `/assets`, `/attack`, `/admin`, `/triage`, `/cases`.

### Postgres databases

`incident_api`, `asset_registry`, `threat_intel`, `integration_hub`, `response_orchestrator`, `notification_service`, `training_orchestrator` (+ optional `smoke`).

### Infra

Root overlays:
- [`docker-compose.platform.yml`](../docker-compose.platform.yml) — Redpanda, Postgres, OpenSearch, MinIO, Redis, MLflow on the **same Compose project network** as `web`/`qdrant` (do not force a separate network name).
- [`docker-compose.detection-core.yml`](../docker-compose.detection-core.yml) — minimal ingest + smoke-consumer + incident-api + asset-registry.
- [`docker-compose.detection-apps.yml`](../docker-compose.detection-apps.yml) — full detection service set (`deploy/detection/compose/docker-compose.apps.yml`).

**One Qdrant only** (existing `qdrant` service). Smoke: `pwsh scripts/smoke_detection_infra.ps1`.

### Human auth

Black Onyx session cookies. Detection APIs are reached via `/api/v1/detection/*` BFF with a short-lived JWT. Browser never holds service keys.

## Routine filesystem backup

Stop the service when possible, then back up the entire state directory and a Qdrant snapshot. If live SQLite backup is unavoidable, use SQLite's backup API rather than copying only the main file because WAL data may not yet be checkpointed.

Restore application state and Qdrant from the same recovery point. Verify authentication, job history, collection counts, case/watchlist contents, triage queues, connectors, and chat ownership before deleting the previous deployment.
