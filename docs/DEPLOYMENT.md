# Deployment guide

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

## Compose deployment

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

The same smoke runs in CI against a disposable core overlay. It verifies exact
ingest persistence plus tenant-scoped asset-registry and incident-api write/read
round trips; it is not proof of trained-model inference, CAPE detonation, GPU
paths, or a Kubernetes rollout.

Prefer root overlays (`docker-compose.platform.yml`, `docker-compose.detection-*.yml`) over `detection/infrastructure/docker-compose/` legacy stacks.

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

Helm rendering is CI-validated, but no live cluster rollout is claimed here. Kubernetes
CNI/eBPF network telemetry is a separately deferred roadmap capability; the supported
network inputs remain the documented flow, Zeek, DNS, and collector paths.

## Backup and upgrade

Before upgrading, stop the application and snapshot both `storage.state_dir` and Qdrant at the same recovery point. Validate Compose, run database migration in a staging copy, verify authentication and collection counts, and then replace the production instance. See [Migration and backup](MIGRATIONS.md).

## Release acceptance

A rendered Compose file is only static validation. Before release, verify the image build, container user, health checks, proxy headers, Secure cookie, unauthenticated API/SSE/WebSocket rejection, volume persistence, backup restore, and absence of `.env`, state, data, and GGUF content from the build context.
