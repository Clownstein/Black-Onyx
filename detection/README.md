# Black Onyx — detection plane

Absorbed AutoAnalyzer detection stack: multi-modality processors, Kafka/Postgres spine, incident API, asset registry, and related services. Product UI and cookie/CSRF auth live in the Black Onyx web/BFF shell — not a separate detection frontend.

Canonical ops: [`docs/DEVELOPMENT.md`](../docs/DEVELOPMENT.md) · Absorption: [`docs/ABSORPTION_CHECKLIST.md`](../docs/ABSORPTION_CHECKLIST.md) · Spec history: [`ANOMALY_DETECTION_PLATFORM.md`](ANOMALY_DETECTION_PLATFORM.md)

## Stack

| Layer | Tech |
| --- | --- |
| Ingestion | **Go** (`services/ingestion-gateway`) |
| Processors / APIs / models | **Python 3.12+** (unique package names per service) |
| UI | Black Onyx web (`web/`) via `/api/v1/detection/*` BFF |
| Broker / data | Redpanda, PostgreSQL, OpenSearch, MinIO, Redis, MLflow |
| Vector search | Shared platform **Qdrant** + `packages/black_onyx_vector` |

## Prerequisites

- Python 3.12+, [uv](https://github.com/astral-sh/uv)
- Go 1.22+
- Node.js 20+ (for `web/`)
- Docker Compose

## Quick start (repo root)

Prefer root Compose overlays so TIP (`web`, Qdrant) and detection share one project network:

```powershell
# Infra (Postgres, Redpanda, OpenSearch, …) — same network as docker-compose.yml
docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d

# Core apps for ingest smoke
docker compose -f docker-compose.yml -f docker-compose.platform.yml `
  -f docker-compose.detection-core.yml up -d --build
powershell -File scripts/smoke_detection_infra.ps1

# Full detection service set
docker compose -f docker-compose.yml -f docker-compose.platform.yml `
  -f docker-compose.detection-apps.yml up -d --build
```

Parity / BFF checks:

```powershell
$env:PYTHONPATH = "src"
uv run pytest tests/test_detection_parity.py tests/test_detection_auth.py -q
```

### Helm

Chart: [`deploy/detection/helm/black-onyx-detection/`](../deploy/detection/helm/black-onyx-detection/)

```bash
helm template black-onyx-detection deploy/detection/helm/black-onyx-detection/
```

### Legacy Compose (deprecated)

The duplicate anomaly-platform Compose entrypoint has been removed. Use root `docker-compose.platform.yml` + `docker-compose.detection-*.yml`. Optional observability/OTEL overlays under `detection/infrastructure/docker-compose/` join the root Compose `default` network.

## Packages and layout

Paths are relative to the **repository root** unless noted:

| Path | Purpose |
| --- | --- |
| `contracts/` | Envelope, findings/incidents, security packs, Qdrant payload schemas |
| `packages/black_onyx_*` | Shared Python libs (contracts, otel, vector, calibration) |
| `services/` | Gateway, processors, APIs, correlation, embedding, SOAR, MLOps |
| `detection/` | Workspace meta, tests, profiles, ops docs, legacy infra |
| `web/src/detection/` | Embedded detection console modules |
| `deploy/detection/` | Helm + DB init for platform Compose |

## Key ports (platform Compose)

Host ports bind to `127.0.0.1` by default. See root `docker-compose.platform.yml` / `docker-compose.detection-*.yml` for the live map. Common lab values:

| Service | Typical host port |
| --- | --- |
| ingestion-gateway | 8080 |
| asset-registry | 8081 |
| incident-api | 8083 |
| Kafka (Redpanda external) | 19092 |
| Postgres | 5432 |

Default lab ingest key: `dev-ingest-key` (`X-API-Key`).

## Testing

```powershell
# Detection contract tests (from detection/)
cd detection; uv sync --extra dev; uv run pytest tests/contract -q

# Go gateway
cd services/ingestion-gateway; go test ./...

# Black Onyx web
cd web; npm ci; npm run build
```

## Security Profiles

Packs under `detection/profiles/`. APIs on `incident-api`; UI under Black Onyx `/security-profiles` / detection console routes.
