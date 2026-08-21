# Terraform inputs for external detection data-plane

Minimal documentation modules — **not** a multi-cloud production stack. The
Helm chart at `deploy/detection/helm/black-onyx-detection/` assumes Postgres,
Redpanda/Kafka, and Redis already exist. These modules declare variables and
outputs that mirror those assumptions so platform teams can wire remote state
or data sources without inventing a second broker inside the chart.

## Layout

| Path | Role |
| --- | --- |
| `modules/postgres/` | External Postgres connection inputs/outputs |
| `modules/kafka/` | External Redpanda/Kafka brokers |
| `modules/redis/` | External Redis URL for correlation HA |

## Usage sketch

```hcl
module "postgres" {
  source = "./modules/postgres"
  host   = "postgres.example.internal"
  port   = 5432
  database_names = [
    "incident_api",
    "asset_registry",
    "threat_intel",
    "training_orchestrator",
  ]
}

module "kafka" {
  source  = "./modules/kafka"
  brokers = ["redpanda.example.internal:9092"]
}

module "redis" {
  source = "./modules/redis"
  url    = "redis://redis.example.internal:6379/0"
}
```

Pass outputs into Helm values (`incidentApi.kafkaBrokers`,
`correlationEngine.redisUrl`, service `databaseUrl` strings) via your CD
pipeline. Do **not** commit live credentials here.

## Non-goals

- Provisioning VPCs, managed Kafka clusters, or multi-region failover.
- Replacing Compose for local labs.
- Shipping a root module that applies against a cloud account by default.
