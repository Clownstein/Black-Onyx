# Development

## Supported toolchain

| Component | Supported line |
| --- | --- |
| Python (application and service images) | 3.12 |
| TypeScript | 5.x within the ESLint parser range `>=4.8.4 <6.1.0` |
| Security gateway and runner base | `debian:sid-slim`, pinned by digest |
| Redpanda | v24.3 (`redpandadata/redpanda`, digest-pinned) |

## Dependency updates

Dependabot groups Docker, Compose, and Python updates across directories, and updates ESLint, `@eslint/js`, `typescript-eslint`, `globals`, and TypeScript together as one toolchain. The root `uv.lock` covers the shared `packages/*` workspace; standalone services without lockfiles use pip manifest updates. Locally built `black-onyx` and `black-onyx/*` images are excluded from registry version discovery.

Patch and digest updates apply within the supported lines above. Moving to a new major line (Python, Torch/torchvision, Postgres, OpenSearch, MLflow, Redis, Grafana, Tempo, Redpanda, or the gateway's Debian base) is a coordinated change: it needs native-wheel and CUDA/ONNX import checks, configuration and API compatibility checks, backup/restore and rollback rehearsal for persistent stores, and final-image startup and vulnerability scans. Keep the gateway and runner on Debian Sid; reject update proposals that switch them to a stable Debian release.

Merge an update only after its final commit passes source tests, Compose/Helm rendering, and final-image build, import, startup, and scan checks. Security alerts always require review; closing an update PR does not fix the underlying vulnerability.

The installable package requires Python 3.12+ and lives at `src/black_onyx` with console scripts `black-onyx` and `black-onyx-web`. It consumes the local `black-onyx-contracts` workspace package, so prefer `uv sync --extra dev`; direct pip installs must include that workspace package. Set `PYTHONPATH=src` only when all declared dependencies are already installed.

For a full local AI + feeds stack, also install optional extras:

```powershell
uv sync --extra llm --extra threat-intel --extra image --extra dev
```

## Host-mode operator stack

Typical lab: TIP and Ollama on the host; Qdrant (and optionally detection) in Docker.

```powershell
# .env often sets BLACK_ONYX_PORT=8100 and QDRANT_HTTP_PORT=16333
Copy-Item config.operator.local.example.yaml config.yaml   # or merge into existing config.yaml
# Load project .env into the shell, then:
uv run black-onyx-web --host 127.0.0.1 --port 8100
```

When TIP is **not** on the Compose network, set `BLACK_ONYX_*_URL` to loopback (see [CONFIGURATION.md](CONFIGURATION.md)) and publish detection lab ports:

```powershell
docker compose -f docker-compose.yml -f docker-compose.platform.yml `
  -f docker-compose.detection-core.yml -f docker-compose.detection-lab-ports.yml up -d --build
```

Without detection upstreams, `/incidents`, `/hunt`, `/malware`, and related pages show **502** `Detection upstream unavailable`. Monitor with **Detection → Services** or `GET http://127.0.0.1:8083/health/live` (and peers). See [AI.md](AI.md).

## Security tools stack

The security-tools stack adds the LLM backends, security gateway, and runner. Download
model files first (see [DEPLOYMENT.md](DEPLOYMENT.md#model-download)), then:

```powershell
# Generate security tokens (or set in .env)
$env:SECURITY_GATEWAY_KEY = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$env:SECURITY_RUNNER_TOKEN = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
# The runner refuses tag-only images, so resolve the pulled image to its digest.
docker pull python:3.12.14-slim
$env:SECURITY_SANDBOX_IMAGE = docker image inspect python:3.12.14-slim --format '{{index .RepoDigests 0}}'

# Start TIP + security tools (includes llama-server, vllm-antares, gateway, runner)
docker compose -f docker-compose.yml -f docker-compose.security-tools.yml up -d

# Optional: with FunctionGemma tool router
docker compose -f docker-compose.yml -f docker-compose.security-tools.yml --profile tool-router up -d

# Verify
docker ps --filter "name=blackonyx"
curl http://127.0.0.1:8081/health    # llama-server (Black-Onyx-5B)

# Smoke test (requires a session cookie; log in first)
python scripts/smoke_security_tools.py --base http://127.0.0.1:8100 --session <cookie> --csrf <csrf>
```

Security gateway tests:

```powershell
cd services/security-gateway
$env:PYTHONPATH = (Get-Location)
uv run pytest tests -q
```

Security runner tests:

```powershell
cd services/security-runner
$env:PYTHONPATH = (Get-Location)
uv run pytest tests -q
```

See [MODELS.md](../MODELS.md) for model architecture and
[BLACK_ONYX_5B_INTEGRATION.md](BLACK_ONYX_5B_INTEGRATION.md) for LLM configuration.

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

The repository intentionally does not retain `.venv` or `web/node_modules`. Run
`uv sync --extra dev` before backend tests and `npm ci` before frontend tests. On
managed Windows, set `UV_CACHE_DIR` to a writable repository-local directory and use
the project Python; system Python may not contain the locked dependencies.

## Detection plane

Detection code lives under `services/`, `contracts/`, `packages/`, and `detection/`. Each Python service uses a unique package name (for example `incident_api`).

```powershell
# Infra (same Compose project network as web/qdrant)
docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d
# Minimal apps for ingest smoke (no host ports by default; the BFF uses Compose DNS)
docker compose -f docker-compose.yml -f docker-compose.platform.yml -f docker-compose.detection-core.yml up -d --build
# Smoke uses docker exec on the Compose network; the lab-ports overlay is not required
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

Shared libs live in `packages/black_onyx_*` (import as `black_onyx_*`). Helm chart: `deploy/detection/helm/black-onyx-detection/`. Prefer root `docker-compose.platform.yml` / `docker-compose.detection-*.yml` over extra files under `detection/infrastructure/docker-compose/`.

Training requests with `run_async=true` require `training-worker`. Real jobs must
provide `dataset_path` with `dataset_reviewed=true`; `demo_synthetic=true` is rejected unless
`TRAINING_ORCHESTRATOR_ALLOW_SYNTHETIC_TRAINING=true`. Synchronous execution is also
disabled unless `TRAINING_ORCHESTRATOR_ALLOW_SYNCHRONOUS_TRAINING=true`; production
submits durable asynchronous jobs.
Trainers must emit a non-empty model plus metrics, thresholds, config, and calibration
artifacts.

Prometheus / Grafana / Loki / Tempo are an **optional** observability overlay (`detection/infrastructure/docker-compose/docker-compose.observability.yml`), not part of the default platform or detection-apps stack. Soft-smoke: `powershell -File scripts/smoke_observability.ps1` (skips if Prometheus is not running).

## Frontend

Canonical brand art lives at the repository root: `BlackOnyxBackground.png` and `BlackOnyxTransparentLogo.png`. Vite serves them as `/background.png` and `/logo.png` in development and emits both into `web/dist` during builds; do not keep copies under `web/` or elsewhere in the repository. A missing file intentionally fails the frontend build. Identity notes and hex tokens are in [docs/brand/README.md](brand/README.md).

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

Playwright starts an isolated state directory and local application server for invitation, registration, login, logout, and role-guard acceptance. This hermetic suite disables external feed/connector polling and isolates Qdrant; use the Compose smoke and configured model dependencies to exercise vector search and ingestion. Browsers install into `.playwright-browsers/`, which `playwright.config.ts` also resolves by default. The suite needs a current `web/dist` build, so run the Vite build first. Set `E2E_BASE_URL` to run against an already deployed stack.

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
docker build --build-arg UV_CACHE_MOUNT=1 --build-arg UV_OFFLINE=1 --cache-from black-onyx:1.0.0 -t black-onyx:1.0.0 .
docker compose up -d --force-recreate --no-deps web
```

Omit `UV_OFFLINE=1` only when the lockfile gained new packages, and keep `UV_CACHE_MOUNT=1` on that build so the wheels stay in the BuildKit cache. Compose volumes are named `black-onyx_*`; model and Qdrant data in them survives rebuilds.

Compose rendering is not runtime acceptance. A release also requires a running Docker engine, a successful image build, non-root container inspection, health checks, proxy/TLS verification, secure-cookie inspection, and confirmation that neither `.env` nor GGUF files entered the build context.
