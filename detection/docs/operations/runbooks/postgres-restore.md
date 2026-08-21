# Runbook: PostgreSQL restore

1. Stop writers that depend on the damaged primary (incident-api, asset-registry) if restore requires exclusive access.
2. Restore from automated backup to a new instance or PITR target (RPO 15 minutes).
3. Validate row counts for `incidents`, `assets`, `ingested_events`.
4. Re-point service DSNs / secrets.
5. Run `/health/ready` and a tenant-isolation smoke test.
6. Document restore time against RTO 4 hour objective.
