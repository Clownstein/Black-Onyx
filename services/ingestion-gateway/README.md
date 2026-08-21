# Ingestion Gateway (Go)

HTTP ingest service that validates common event envelopes and publishes to Redpanda.

## Build

Requires Go 1.22+. From this directory:

```bash
go mod tidy
go test ./...
go run ./cmd/server
```

Docker (build context = repository root):

```bash
docker build -f services/ingestion-gateway/Dockerfile -t ingestion-gateway .
```

## Configuration

| Env | Default | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | HTTP bind address |
| `API_KEYS` | `dev-ingest-key` | Comma-separated `X-API-Key` values |
| `KAFKA_BROKERS` | `localhost:19092` | Redpanda/Kafka brokers |
| `TOPIC_LOGS_RAW` | `logs.raw` | Success topic |
| `TOPIC_INGEST_DLQ` | `ingest.dlq` | Shared dead-letter topic for failed/invalid ingest |
| `MAX_BODY_BYTES` | `1048576` | Request size limit |
| `MAX_BATCH_SIZE` | `100` | Max events per request |
| `MAX_FUTURE_SKEW_SECONDS` | `300` | Reject timestamps too far ahead |
| `MAX_EVENT_AGE_SECONDS` | `86400` | Reject very old `occurred_at` |
