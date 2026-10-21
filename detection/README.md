# Detection plane

Kafka/Postgres detection services used by Black Onyx: ingestion, modality
processors, correlation, incidents, assets, hunt, malware, and response.

The UI is the Black Onyx web app (`web/`) through `/api/v1/detection/*`. There
is no separate detection frontend.

| Guide | Path |
| --- | --- |
| Architecture | [docs/DETECTION_PLATFORM.md](../docs/DETECTION_PLATFORM.md) |
| Compose and tests | [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md) |
| Ops, collectors, ADRs | [docs/README.md](docs/README.md) |

## Stack

| Layer | Tech |
| --- | --- |
| Ingestion | Go (`services/ingestion-gateway`) |
| Processors and APIs | Python 3.12+ (one package name per service) |
| UI | Black Onyx web via the detection BFF |
| Broker / data | Redpanda, PostgreSQL, OpenSearch, MinIO, Redis, MLflow |
| Vectors | Shared Qdrant (`packages/black_onyx_vector`) |

## Start (repo root)

```powershell
docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d
docker compose -f docker-compose.yml -f docker-compose.platform.yml `
  -f docker-compose.detection-core.yml up -d --build
powershell -File scripts/smoke_detection_infra.ps1
docker compose -f docker-compose.yml -f docker-compose.platform.yml `
  -f docker-compose.detection-apps.yml up -d --build
```

Helm chart: [`deploy/detection/helm/black-onyx-detection/`](../deploy/detection/helm/black-onyx-detection/).
Use root Compose overlays only. Optional observability files under
`detection/infrastructure/docker-compose/` join the same Compose network.

Layout: `contracts/`, `packages/black_onyx_*`, `services/`, `detection/`,
`web/src/detection/`, `deploy/detection/`. Security packs live in
`detection/profiles/`.
