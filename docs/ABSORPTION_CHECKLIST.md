# Feature / DB / UI parity checklist (AutoAnalyzer → Black Onyx)

Absorbed trees: `services/`, `contracts/`, `packages/`, `detection/`, `web/src/detection/`, `deploy/detection/`.
`AutoAnalyzer/` removed after port.

**Honesty legend:** `[x]` = present in tree **and** covered by automated tests or a repeatable CI smoke path.
`[x]*` = wired in code/compose; runtime remains operator-run or lab-only.
Unchecked items are incomplete.

## UI (in `web/src` + gallery tiles)

- [x] `/detection` overview
- [x] `/incidents`, `/incidents/:id`
- [x] `/findings`, `/findings/:id`
- [x] `/hunt`
- [x] `/malware`
- [x] `/attack-coverage`
- [x] `/models`
- [x] `/detection-services`
- [x] `/detection/metrics`, `/detection/network`, `/detection/code-changes`
- [x] `/assets` (Postgres asset-registry SoR; legacy SQLite rows are explicit migration candidates only)
- [x] Assets CSV/create/PATCH/soft-delete write registry only and fail closed
- [x] `/data-health`
- [x] `/response-queue`
- [x] `/security-profiles`
- [x] `/admin` (TIP + detection ops embedded; `/detection-admin` redirects)
- [x] Triage maps `incident_id` (not `id`) for detection-spine write-back — covered by `web/src/detection/triage_ids.test.ts`
- [x] Playbooks links to SOAR response-queue
- [x] Hunt ↔ Search reciprocal entry points
- [x] Cases UI links `external_incident_id` → `/incidents/:id`

## Postgres / Kafka

- [x] Init SQL under `deploy/detection/init/`
- [x] Alembic versions under `deploy/detection/migrations/{service}/`
- [x] Topic bootstrap in `docker-compose.platform.yml` (Compose validation plus a successful live `redpanda-init` run)
- [x] Parity tests: `tests/test_detection_parity.py`

## Services

- [x] All services under `services/` with **unique package names** (no top-level `app`)
- [x] Compose/Dockerfile uvicorn module paths updated
- [x]* Collectors, profiles, playbooks, pipelines, contracts, and packages are unit/contract-tested; a live private-network ingest-to-Kafka-to-Postgres event was proven, while full collector/processor coverage remains lab-only
- [x] Scanner image runs Semgrep repository rules and checksum-pinned CodeQL 2.25.5; live fixtures produced `owasp-asvs-eval-use` and `py/sql-injection`
- [x]* All four trained model images were built and live-proven non-ready without external artifacts; real artifact inference remains lab-only and unproven
- [x]* Malware orchestration fails closed without CAPE; live isolated-lab detonation remains unproven
- [x]* Production model training: platform-shaped example formats, loaders, and training-orchestrator paths under `detection/models/*/training/` are wired for log/network/metrics/code; Compose mounts repo at `/repo` via `TRAINING_ORCHESTRATOR_REPO_ROOT`. Live training with reviewed real datasets and a configured trainer backend remains lab-only.

## Auth / BFF / overlap

- [x] `POST /api/v1/auth/detection-token` returns **410** (BFF-only minting; no browser-held detection JWT)
- [x] `/api/v1/detection/*` BFF: mutations require analyst; session actor injection; PyJWT mint — automated tests plus live incident and response create/ack/disposition/approve/reject smoke
- [x] Cases `external_incident_id` (+ `POST /api/v1/detection-incidents/promote`) — unit-tested in `tests/test_absorption_overlap.py`
- [x] Triage disposition/ack write-back uses Postgres incident SoR ids (unit-tested mapping)
- [x] Shared Qdrant only (no second Qdrant in platform compose)
- [x] TI write rules documented (match vs publish)
- [x] TIP → Postgres `threat_intel` sync (`sync_indicators_to_threat_intel`) — unit-tested in `tests/test_absorption_overlap.py`
- [x] TIP assets migrate to registry (`POST /api/v1/assets/migrate`) — unit-tested and live-smoked twice against an isolated TIP state with one registry asset
- [x] Service packages: no `app` pyproject/uvicorn leftovers
- [x] Detection compose: `OIDC_DISABLED=false` + `OIDC_HS_SECRET` on incident-api / asset-registry
- [x] Browser detection client has **no** `VITE_*` S2S keys (BFF injects server-side)
- [x] Backup/restore validates a versioned manifest and restores SQLite + Qdrant snapshots (security tests plus isolated live Qdrant smoke)

**Note:** Detection services default to fail-closed OIDC (`OIDC_DISABLED=false`; demo `X-Role` / ingest keys off unless explicitly enabled). Local RBAC and demo-key experiments require joining `docker-compose.detection-lab-dev.yml` after detection-core/apps — do not weaken production defaults.

## Compose / CI / Helm

- [x] `docker-compose.platform.yml` (shared project network with TIP)
- [x] `docker-compose.detection-core.yml` (no host ports by default)
- [x] `docker-compose.detection-lab-ports.yml` (explicit lab loopback ports only)
- [x] `docker-compose.detection-apps.yml`
- [x] `scripts/smoke_detection_infra.ps1` runs in CI against a hermetic core overlay: exact private-network ingest persistence, tenant-scoped asset and incident write/read persistence, and cleanup without host ports
- [x] `.github/workflows/black-onyx-ci.yml` (full TIP/web/service matrix, migration parity, compose, helm)
- [x]* Helm chart `deploy/detection/helm/black-onyx-detection/` renders base, production, and air-gap profiles; no live cluster rollout is proven
- [x] `AutoAnalyzer/` tree absent
- [x] Go modules `github.com/black-onyx/*` (ingestion-gateway + contracts)
- [x] Shared libs renamed to `packages/black_onyx_*`
- [x] CI: detection parity + package import smoke + `go test` for ingestion-gateway
- [x] CI: web unit/lint/build plus Playwright auth and lazy detection-route acceptance; Compose config, hermetic runtime smoke, and `helm template`
- [x] Detection meta-package `black-onyx-detection` + regenerated `detection/uv.lock`
- [x] Orphan detection Vite SPA entrypoints removed
- [x] Orphan `AppShell` / unused detection Assets page removed
- [x] Detection README + AGENTS point at root Compose/Helm (legacy infra deprecated)
- [x] Detection apps compose uvicorn overrides use unique packages (no `app.main:app`)
- [x] Assets create/CSV write Postgres registry SoR only (TIP migrate remains one-way)
- [x] Detection apps container names use `blackonyx-*` (not `ap-*`)
- [x] Detection apps Compose lives under `deploy/detection/compose/`; model Dockerfiles COPY `detection/models/`
- [x] Legacy `anomaly-platform` stack is not a supported or runnable deployment path
- [x] Observability/OTEL overlays join root Compose `default` network (`blackonyx-*` names)
- [x] K8s namespace manifests + network policies use `black-onyx-*` (aligned with Helm values)
- [x] Grafana/Prometheus alert group branding uses Black Onyx names

## Runtime proof still external

- [x] Five supported Compose overlay combinations validate; CI additionally runs a disposable core stack for ingest persistence plus tenant-scoped incident/asset write-read proof. TIP auth/CSRF, response-orchestrator write-back, Kafka topic-init failure recovery, and Qdrant backup/restore remain separate evidence paths.
- [x] CodeQL 2.25.5 and Semgrep executed fixture scans inside the built image with normalized findings
- [x]* External trained models, CAPE/DRAKVUF, GPU paths, and Helm cluster behavior remain lab-only
