# Application OpenTelemetry instrumentation

Guidance for emitting traces/metrics/logs into the optional Black Onyx collector → Tempo path.

Ops summary: [`detection/docs/operations/otel-app-instrumentation.md`](../../../docs/operations/otel-app-instrumentation.md).

## Local collector

```bash
docker compose -f docker-compose.yml -f docker-compose.platform.yml \
  -f detection/infrastructure/docker-compose/docker-compose.otel.yml up -d
```

Collector config: `detection/infrastructure/docker-compose/otel-collector-config.yaml`

| Protocol | Endpoint (host) | Endpoint (compose network) |
| --- | --- | --- |
| OTLP HTTP | `http://127.0.0.1:4318` | `http://otel-collector:4318` |
| OTLP gRPC | `127.0.0.1:4317` | `otel-collector:4317` |

Platform Python services call `black_onyx_otel.setup_tracing("<service>")` and honor `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`.
