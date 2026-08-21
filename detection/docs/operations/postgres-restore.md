# Runbook: Postgres restore

## Symptoms

- Incident API / asset registry readiness failures
- Corruption or accidental destructive writes
- Failed migration requiring point-in-time recovery

## Impact

- Read/write APIs unavailable or inconsistent
- Correlation / notification side effects may fail

## Immediate actions

1. Stop writers that depend on the damaged database (scale APIs to 0 if needed).
2. Identify the latest verified backup (snapshot / base backup + WAL).
3. Restore into a new instance or volume; do not overwrite the only remaining backup.

## Recovery

1. Restore base backup.
2. Replay WAL to the chosen recovery target.
3. Run schema/version checks (`alembic current` where applicable).
4. Point services at the restored DSN via secret update and roll pods.
5. Re-run retention job in dry-run mode to confirm policies still apply.

## Verification

- `/health/ready` green for incident-api and asset-registry
- Spot-check incidents, assets, and audit rows
- Confirm replicas/streaming replication (if configured) are healthy
