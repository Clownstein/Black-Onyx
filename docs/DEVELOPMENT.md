# Development and verification

The installable package requires Python 3.12+ and lives at `src/black_onyx` with console scripts `black-onyx` and `black-onyx-web`. It consumes the local `black-onyx-contracts` workspace package, so prefer `uv sync --extra dev`; direct pip installs must include that workspace package. Set `PYTHONPATH=src` only when all declared dependencies are already installed.

## Backend

```powershell
$env:PYTHONPATH = "src"
$env:BLACK_ONYX_AUTH_SECRET = "compose-validation-only"
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest-tmp\verification
.\.venv\Scripts\python.exe -m compileall -q src
$env:UV_CACHE_DIR = ".uv-cache"
uv lock --check
```

Unit tests cover extraction, migrations, authentication, invitations, resets, RBAC, CSRF, analytics/triage metrics, backup continuity, managers, ingestion behavior, reports, feeds, connectors, and security contracts. Integration tests should mock LLM/enrichment HTTP boundaries and use an isolated Qdrant instance.

## Detection spine (absorbed AutoAnalyzer)

Detection code lives under `services/`, `contracts/`, `packages/`, and `detection/` — not under `AutoAnalyzer/` (removed). Each Python service uses a **unique package name** (e.g. `incident_api`, not `app`).

```powershell
# Infra (same Compose project network as web/qdrant)
docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d
# Minimal apps for ingest smoke (no host ports by default — BFF uses Compose DNS)
docker compose -f docker-compose.yml -f docker-compose.platform.yml -f docker-compose.detection-core.yml up -d --build
# Smoke uses docker exec on the Compose network — lab-ports overlay is NOT required
powershell -File scripts/smoke_detection_infra.ps1

# Optional lab-only loopback ports (127.0.0.1:8080/8081/8083) for host curl/debug:
docker compose -f docker-compose.yml -f docker-compose.platform.yml `
  -f docker-compose.detection-core.yml -f docker-compose.detection-lab-ports.yml up -d --build

# Full detection service set (fail-closed: demo keys off, OIDC required; set API_KEYS or join lab-dev)
$env:API_KEYS = "dev-ingest-key"
docker compose -f docker-compose.yml -f docker-compose.platform.yml -f docker-compose.detection-apps.yml up -d --build

# Lab-only: re-enable demo/service keys + default lab ingest key (and optional OIDC_DISABLED=true)
docker compose -f docker-compose.yml -f docker-compose.platform.yml `
  -f docker-compose.detection-apps.yml -f docker-compose.detection-lab-dev.yml up -d --build

# Parity
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m pytest tests/test_detection_parity.py tests/test_detection_auth.py -q
```

Shared libs live in `packages/black_onyx_*` (import as `black_onyx_*`). Do not add new features under a staging AutoAnalyzer tree. Helm chart: `deploy/detection/helm/black-onyx-detection/`. Prefer root `docker-compose.platform.yml` / `docker-compose.detection-*.yml` over legacy `detection/infrastructure/docker-compose/`.

Prometheus / Grafana / Loki / Tempo are an **optional** observability overlay (`detection/infrastructure/docker-compose/docker-compose.observability.yml`), not part of the default platform or detection-apps stack. Soft-smoke: `powershell -File scripts/smoke_observability.ps1` (skips if Prometheus is not running).

## Frontend

Canonical brand art lives at the repository root: `BlackOnyxBackground.png` and `BlackOnyxTransparentLogo.png`. Vite serves them as `/background.png` and `/logo.png` in development and emits both into `web/dist` during builds; do not maintain duplicate copies under `web/`. A missing file intentionally fails the frontend build. Keep `background.png` at the root as a sync of the background art for tools that still expect that filename. Identity notes and hex tokens are in [docs/brand/README.md](brand/README.md).

Shared visual tokens and responsive primitives live in `web/src/styles.css`; reusable page headings, empty states, notices, errors, data surfaces, and confirmations live in `web/src/ui.tsx`. Keep workflow-specific composition in its workflow module rather than adding page-name selectors to the global stylesheet. New pages should provide a purposeful empty state and keep primary actions distinct from secondary and destructive actions. When adding a route, also add a gallery tile in `web/src/gallery/tile_registry.ts` and keep RBAC in the shared `visibleFor` helper.

```powershell
Push-Location web
npm install
node node_modules/typescript/bin/tsc -b
node node_modules/vitest/vitest.mjs run --configLoader runner
node node_modules/vite/bin/vite.js build --configLoader runner
node node_modules/eslint/bin/eslint.js src
$env:PLAYWRIGHT_BROWSERS_PATH = (Resolve-Path ../.playwright-browsers)
node node_modules/playwright/cli.js install chromium
node node_modules/playwright/cli.js test
Pop-Location
```

Vitest covers the CSRF/session client, streaming event parser, role-aware actions, and typed destructive confirmation. Add React Testing Library coverage whenever a workflow or role rule changes.

Playwright starts an isolated state directory and local application server for invitation, registration, login, logout, and role-guard acceptance. The hermetic server disables external feed/connector polling and uses an explicit unavailable-Qdrant boundary, so this suite does not claim vector-store or ingestion coverage. Browsers install into `.playwright-browsers/`, which `playwright.config.ts` also resolves by default. The suite needs a current `web/dist` build, so run the Vite build first. Set `E2E_BASE_URL` to run against an already deployed stack. Full ingestion/search acceptance additionally requires Qdrant and the configured model dependencies.

CI installs Chromium and runs this suite after the production build, including an administrator visit to the lazily-loaded detection console. The core detection Compose runtime smoke is separate: it starts a disposable private-network stack, verifies Kafka-to-Postgres ingest persistence and tenant-scoped asset/incident write-read persistence, then removes volumes.

If Chrome is already installed and browser downloads are unavailable, set `$env:E2E_BROWSER_CHANNEL = "chrome"` before `npm run test:e2e`. Omit it in CI when using the pinned Playwright Chromium installation.

## Deployment contracts

```powershell
$env:BLACK_ONYX_AUTH_SECRET = "compose-validation-only"
docker compose config --quiet
docker build --check .
```

### Slow-link / cache-friendly Docker rebuilds

Avoid `docker compose build --no-cache` and `docker builder prune` unless you intend to re-pull torch and friends.

UI-only (seconds, no image rebuild):

```powershell
Push-Location web; npm run build; Pop-Location
docker compose cp web\dist\. web:/app/web/dist/
# Or resolve the container id: docker compose ps -q web
```

Full image using local BuildKit + uv/npm caches (no multi-GB redownload when wheels are already cached):

```powershell
$env:DOCKER_BUILDKIT = "1"
docker build --build-arg UV_OFFLINE=1 --cache-from black-onyx:1.0.0 --cache-from defenders-chat:1.0.0 -t black-onyx:1.0.0 -t defenders-chat:1.0.0 .
docker compose up -d --force-recreate --no-deps web
```

Omit `UV_OFFLINE=1` only when the lockfile gained new packages. Compose volume names stay on `defenderchat_*` so model/Qdrant data is not abandoned onto empty volumes after a rename.

Compose rendering is not runtime acceptance. A release also requires a running Docker engine, a successful image build, non-root container inspection, health checks, proxy/TLS verification, secure-cookie inspection, and confirmation that neither `.env` nor GGUF files entered the build context.
