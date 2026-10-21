# OTEL application instrumentation

Instrument first-party apps so traces and metrics reach the optional collector → Tempo path. Platform Python services call `black_onyx_otel.setup_tracing`.

## Collector

```bash
docker compose -f docker-compose.yml -f docker-compose.platform.yml \
  -f detection/infrastructure/docker-compose/docker-compose.otel.yml up -d
```

| Listener | Host | Compose network |
| --- | --- | --- |
| OTLP HTTP | `http://127.0.0.1:4318` | `http://otel-collector:4318` |
| OTLP gRPC | `127.0.0.1:4317` | `otel-collector:4317` |

With the observability overlay, the collector can forward to Tempo. Config: `detection/infrastructure/docker-compose/otel-collector-config.yaml`. See `grafana-assistants.md`.

## Config samples

Env and SDK sketches: [`detection/infrastructure/otel/app-instrumentation/`](../../infrastructure/otel/app-instrumentation/).
