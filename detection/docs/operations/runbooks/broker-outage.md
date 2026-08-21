# Runbook: Broker outage

1. Check Redpanda/Kafka health (`rpk cluster health` or cloud console).
2. Ingestion gateway readiness should fail open for monitored apps (collectors buffer).
3. Pause consumers if needed; do not commit offsets during partial failure.
4. Restore broker quorum/replication; confirm topic ISR.
5. Replay from retained offsets or time range; verify idempotent processors prevent duplicate findings.
6. Drain DLQ for poison messages after root-cause fix.
