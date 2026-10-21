# Deployment

## Production contract

Black Onyx is a single-instance application-state service backed by SQLite and a separate Qdrant vector store. Terminate TLS at a trusted reverse proxy and do not publish the application or Qdrant containers directly. Horizontal application replicas are unsupported while SQLite is the state database.

Production startup requires:

- an HTTPS `BLACK_ONYX_EXTERNAL_URL`;
- the JSON host list `BLACK_ONYX_ALLOWED_HOSTS`;
- the public `BLACK_ONYX_HOSTNAME`;
- a stable, randomly generated `BLACK_ONYX_AUTH_SECRET` supplied by a secret manager;
- persistent application-state and Qdrant volumes;
- an optional read-only model volume for GGUF files.

The included production Compose override removes direct application/Qdrant ports, uses an internal backend network, and exposes only pinned Caddy. `deploy/nginx.conf.example` is the equivalent contract for an externally managed Nginx proxy.

With the detection plane, layer the production overlays after the apps overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.platform.yml   -f docker-compose.detection-apps.yml -f docker-compose.production.yml   -f docker-compose.production-detection.yml up -d
```

`docker-compose.production.yml` makes the Compose `default` network internal and
removes the loopback ports of Postgres, Redis, Redpanda, OpenSearch, MinIO, MLflow
and SearXNG. `docker-compose.production-detection.yml` attaches only the services
with a real outbound dependency (threat-intel feeds, integration hub, notification
service and outbox worker; SearXNG is attached in the base production overlay) to
an `egress` network. The BFF reaches detection services on `default` and the
internet through `proxy`.

Deployment settings (Compose env and Helm values/secrets) can then be managed from
the admin UI through the deployment controller; see
[operations/deployment-controller.md](operations/deployment-controller.md).

## Model download

Black Onyx uses multiple AI models. The main LLM (Black-Onyx-5B) and the optional
tool router (FunctionGemma) must be downloaded before starting the security-tools
stack. See [MODELS.md](../MODELS.md#model-download-and-setup) for the full inventory.

### Black-Onyx-5B (required for chat and security agent)

```powershell
mkdir models\Black-Onyx-5B -Force

# Download from Hugging Face: Clownstein/Black-Onyx-5B-GGUF
# 1. Black-Onyx-5B-Q8_0.gguf  (4.9 GB)  → models/Black-Onyx-5B/Black-Onyx-5B-Q8_0.gguf
# 2. Black-Onyx-5B-mmproj.gguf (987 MB)  → models/Black-Onyx-5B/Black-Onyx-5B-mmproj.gguf
```

### FunctionGemma 270M (optional tool router)

```powershell
mkdir models\tool-router -Force

# Download from HuggingFace: google/functiongemma-270m-it (GGUF Q8_0)
# functiongemma-270m-it-Q8_0.gguf (278 MB) → models/tool-router/functiongemma-270m-it-Q8_0.gguf
```

### Antares-1B (vulnerability localization)

Ships with the repository at `detection/models/antares-1b/model.safetensors` (3.5 GB).
No download needed.

### Detection modality models

All detection models (log, network, metrics, code, host-state, malware-static) ship
with the repository under `detection/models/`. No download needed.

## First launch

```bash
bash scripts/bootstrap_full_stack.sh
```

That entrypoint layers `docker-compose.yml`, `docker-compose.platform.yml`, `docker-compose.detection-apps.yml`, `docker-compose.security-tools.yml`, `docker-compose.misp.yml`, and `docker-compose.self-monitor.yml`. Host Wazuh is `sudo bash scripts/install_wazuh_host.sh`. Security Lab stays profile-gated; non-lab public scanning is the Settings toggle for `ALLOW_PUBLIC_TARGETS`.

## Compose deployment

### TIP + Qdrant (base stack)

```powershell
$env:BLACK_ONYX_AUTH_SECRET = "generated-and-stored-outside-the-repository"
$env:BLACK_ONYX_EXTERNAL_URL = "https://blackonyx.example.com"
$env:BLACK_ONYX_ALLOWED_HOSTS = '["blackonyx.example.com"]'
$env:BLACK_ONYX_HOSTNAME = "blackonyx.example.com"
docker compose -f docker-compose.yml -f docker-compose.production.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
docker compose run --rm cli users bootstrap-admin --email admin@example.com
```

The image is multi-stage and runs as the unprivileged `blackonyx` user. `.dockerignore` excludes secrets, state, data, caches, build results, dependencies, and all `*.gguf` files. Mount a model explicitly at `/models` when using llama.cpp.

Compose runs the one-shot `state-permissions` service before `web` or `cli`.
It repairs ownership of entries inside the
`black-onyx_checkpoints_data` volume to the application UID/GID (`10001:10001`),
so the non-root app can open every file in it, including files restored from a
backup. The helper mounts only that volume, has no network, a read-only
container filesystem, and only `CAP_CHOWN`; it changes ownership metadata, not
file contents. It refuses symlinks and blocks app startup if repair fails. To
inspect a failure, run `docker compose logs state-permissions`; do not widen the
mount or grant additional capabilities as a workaround.

### Security tools (LLM + 45 cataloged MCP tools)

The security-tools stack adds the LLM backends, security gateway, and security runner.
Download the model files first (see [Model download](#model-download) above), then:

```powershell
# Generate security tokens
$env:SECURITY_GATEWAY_KEY = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$env:SECURITY_RUNNER_TOKEN = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
# The runner refuses tag-only images (a tag can be repointed after review), so
# resolve the pulled image to its immutable digest.
docker pull python:3.12.14-slim
$env:SECURITY_SANDBOX_IMAGE = docker image inspect python:3.12.14-slim --format '{{index .RepoDigests 0}}'

# Start TIP + security tools
docker compose -f docker-compose.yml -f docker-compose.security-tools.yml up -d

# Verify
curl http://127.0.0.1:8081/health          # llama-server (Black-Onyx-5B)
docker exec blackonyx-security-gateway curl -s http://127.0.0.1:8000/health/llm
```

With the optional FunctionGemma tool router:

```powershell
$env:TOOL_ROUTER_ENABLED = "true"
docker compose -f docker-compose.yml -f docker-compose.security-tools.yml --profile tool-router up -d
```

Services started:

| Service | Container | Purpose |
| --- | --- | --- |
| `llama-server` | `blackonyx-llama-server` | Black-Onyx-5B GGUF + mmproj (port 8081 internal) |
| `vllm-antares` | `blackonyx-vllm-antares` | Antares-1B safetensors (port 8000 internal) |
| `tool-router` | `blackonyx-tool-router` | FunctionGemma 270M (optional, port 8080 internal) |
| `security-gateway` | `blackonyx-security-gateway` | Agent loop + tool dispatch |
| `security-sessions-permissions` | (one-shot) | Chowns `SECURITY_SESSIONS_HOST_ROOT` to UID 10001 |
| `security-runner` | `blackonyx-security-runner` | Ephemeral container execution |

Compose creates the sessions bind directory as the host user. The runner and
toolbox run as UID `10001`, so `security-sessions-permissions` repairs ownership
(with `CAP_CHOWN` only) before the runner starts. Inspect failures with
`docker compose logs security-sessions-permissions`.

See [MODELS.md](../MODELS.md) for the full model architecture and
[BLACK_ONYX_5B_INTEGRATION.md](BLACK_ONYX_5B_INTEGRATION.md) for LLM configuration.

### Detection plane (optional overlay)

TIP (web/Qdrant) and detection (Postgres/Kafka/workers) share one Compose project network. Do not start a second Qdrant.

```powershell
# Infra: Postgres, Redpanda, OpenSearch, MinIO, Redis, MLflow
docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d
# Minimal apps for ingest smoke
docker compose -f docker-compose.yml -f docker-compose.platform.yml -f docker-compose.detection-core.yml up -d --build
# Full detection workers
docker compose -f docker-compose.yml -f docker-compose.platform.yml -f docker-compose.detection-apps.yml up -d --build
powershell -File scripts/smoke_detection_infra.ps1
```

The same smoke runs in CI against a disposable core overlay, verifying ingest
persistence and tenant-scoped asset-registry and incident-api write/read
round trips. Validate trained-model inference, CAPE detonation, GPU paths, and
Kubernetes policies with the corresponding deployment profile and environment.

Prefer root overlays (`docker-compose.platform.yml`, `docker-compose.detection-*.yml`) over the optional component stacks under `detection/infrastructure/docker-compose/`.

### Hybrid: host TIP + container detection

TIP defaults BFF upstreams to Compose DNS (`http://incident-api:8083`, …). A host-run TIP must set `BLACK_ONYX_*_URL` to `http://127.0.0.1:…` and use `docker-compose.detection-lab-ports.yml` (or equivalent) so those ports are published. See [CONFIGURATION.md](CONFIGURATION.md).

Port overrides commonly used in lab `.env`:

| Variable | Example | Role |
| --- | --- | --- |
| `BLACK_ONYX_PORT` | `8100` | TIP publish / Vite proxy |
| `QDRANT_HTTP_PORT` | `16333` | Host → container Qdrant HTTP |
| `QDRANT_QDRANT__PORT` / `qdrant.port` | `16333` | TIP client target port |

Ollama on the host from a containerized TIP: `QDRANT_EMBEDDING__OLLAMA_BASE_URL=http://host.docker.internal:11434` (Windows/macOS Docker Desktop).

### Optional observability

Prometheus / Grafana / Loki / Tempo / Alertmanager are an optional overlay, not part of the default platform or detection-apps stack:

```powershell
docker compose -f docker-compose.yml -f docker-compose.platform.yml `
  -f docker-compose.detection-apps.yml `
  -f detection/infrastructure/docker-compose/docker-compose.observability.yml up -d
```

Loopback UIs when enabled: Grafana `:3000`, Prometheus `:9090`, Loki `:3100`, Tempo `:3200`, Alertmanager `:9093`.

## Kubernetes or another orchestrator

Use the same security contract: inject named secrets, mount application state on a single-writer persistent volume, keep Qdrant private, configure readiness against `/api/v1/health`, and route all browser traffic through one HTTPS origin. Restrict proxy trust to the actual ingress address range and preserve `Host` and scheme headers.

The chart deploys the documented detection services against operator-provided
dependencies. Kubernetes CNI/eBPF network telemetry is outside the supported
collector set; supported network inputs are the documented flow, Zeek, DNS,
and cloud-provider collector paths.

The chart does not install Postgres, Kafka, Redis, OpenSearch, Qdrant, MinIO, or model
storage. Configure `externalDependencies.*`, create `black-onyx-detection-secrets` in
each workload namespace, and create the PVC named by
`trainingOrchestrator.packageClaimName` plus the reviewed-dataset PVC named by
`trainingOrchestrator.datasetClaimName` before installation. Database URLs must use
cluster-reachable DNS and must not resolve to localhost. The Secret must also contain
`objectStoreAccessKey` and `objectStoreSecretKey` for PCAP, incident bundle, and malware
artifact access.

Pre-install/pre-upgrade hook Jobs run `alembic upgrade head` for all eight migrated
schemas, and a failure blocks the release. The training API queues asynchronous jobs;
`training-worker` claims them through database leases and writes signed packages to the
shared PVC. Production keeps synthetic training disabled.

Model services pull the signed package each alias must serve from the training
orchestrator (`modelServing.*`); promotion commits only after replicas confirm.
Set `modelServing.tenantId` to the tenant whose aliases the cluster serves. See
[operations/model-serving.md](operations/model-serving.md).

The chart does not deploy Black Onyx web (TIP + detection BFF); run it with Compose
next to the cluster and point its `BLACK_ONYX_*_URL` upstreams at the cluster
services (through ingress or an internal load balancer). Give the BFF the same
producer keys as the chart Secret: `INCIDENT_API_SERVICE_KEY`,
`THREAT_INTEL_SERVICE_KEY`, `INTEGRATION_HUB_API_KEY`,
`RESPONSE_ORCHESTRATOR_API_KEY`, `RESPONSE_ORCHESTRATOR_APPROVER_API_KEY`,
`NOTIFICATION_API_KEY`, `TRAINING_API_KEY`, `MODEL_GATEWAY_API_KEY` and `API_KEYS`,
and set `BLACK_ONYX_DETECTION_TENANT` to `modelServing.tenantId`.

## Backup and upgrade

Before upgrading, stop the application and snapshot both `storage.state_dir` and Qdrant at the same recovery point ([operations/backup-restore.md](operations/backup-restore.md)). Validate Compose, run database migration in a staging copy, verify authentication and collection counts, and then replace the production instance. See [Data and backup](DATA_AND_BACKUP.md).

## Release acceptance

A rendered Compose file is only static validation. Before release, verify the image build, container user, health checks, proxy headers, Secure cookie, unauthenticated API/SSE/WebSocket rejection, volume persistence, backup restore, and absence of `.env`, state, data, and GGUF content from the build context.
