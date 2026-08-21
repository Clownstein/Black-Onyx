# Grafana assistants & platform observability

Optional Compose observability overlay for Black Onyx detection (joins the root Compose project network).

## Run the observability overlay

From the **repo root**:

```bash
docker compose -f docker-compose.yml -f docker-compose.platform.yml \
  -f docker-compose.detection-apps.yml \
  -f detection/infrastructure/docker-compose/docker-compose.observability.yml \
  up -d

# Also export traces from the OTEL collector into Tempo
docker compose -f docker-compose.yml -f docker-compose.platform.yml \
  -f docker-compose.detection-apps.yml \
  -f detection/infrastructure/docker-compose/docker-compose.otel.yml \
  -f detection/infrastructure/docker-compose/docker-compose.observability.yml \
  up -d
```

| Component | Host port | Notes |
| --- | --- | --- |
| Grafana | `3000` | `admin` / `admin` (local only) |
| Prometheus | `9090` | scrapes Compose DNS `/metrics` |
| Loki | `3100` | Alloy ships Docker logs |
| Tempo | `3200` | query API |
| Alertmanager | `9093` | webhook routes |

Provisioned datasources live under `detection/infrastructure/docker-compose/grafana/provisioning/`.

Point Python services at the collector when the OTEL overlay is up:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
```
