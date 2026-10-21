# Runbook: Broker outage

## Symptoms

- Ingestion gateway publish failures / elevated 5xx
- Processor consumer lag climbing
- Alerts on Redpanda/Kafka availability

## Impact

- New events are not durably accepted or not processed
- Detection latency SLO at risk; incident creation stalls

## Immediate actions

1. Confirm broker health (`rpk cluster health` / Kafka broker metrics).
2. Check disk, partition leadership, and under-replicated partitions.
3. If a single broker is unhealthy in a multi-node cluster, drain/restart that node first.
4. Pause non-critical consumers if the cluster is recovering under load.
5. Keep collectors buffering/retrying; do not wipe offsets.

## Recovery

1. Restore quorum / replace failed brokers.
2. Verify topic availability for ingest and DLQ topics.
3. Resume processors; watch lag decrease without duplicate-incident storms (idempotency keys).
4. Replay from retained offsets only if gaps are confirmed.

## Verification

- Ingest success rate returns to baseline
- Consumer lag trending down
- No sustained DLQ growth for valid payloads
