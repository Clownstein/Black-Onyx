# Backup and restore runbook

Backups cover the TIP system of record: every SQLite database and managed extra
file under `storage.state_dir`, plus Qdrant collection snapshots. Detection-plane
Postgres databases are backed up with the platform's Postgres tooling, not here.

Implementation: `src/black_onyx/ops/backup_manager.py`, admin routes under
`/api/v1/admin/backup` in `src/black_onyx/api/routes_backup.py`
(`/inventory`, `/create`, `/restore`, `/upload`, `/{id}/download`, `DELETE /{id}`).

## Create

`POST /api/v1/admin/backup/create` (admin) writes `state_dir/backups/<id>.zip` with a
manifest (SQLite files with integrity-checked copies, extra files, Qdrant
snapshots, format version). The archive is validated before it replaces the
partial file.

After each successful backup, archives beyond `BLACK_ONYX_BACKUP_RETENTION`
(default `7`, `0` keeps all) are deleted oldest first; the new backup is never
pruned. The response lists pruned ids under `pruned`.

## Restore (coordinated and recoverable)

1. The archive is validated and unpacked into `backups/.restore-<id>`.
2. Every staged SQLite file passes `PRAGMA integrity_check` before anything live
   changes.
3. The current SQLite files, extra files and Qdrant collections are saved into a
   rollback folder.
4. **Qdrant is restored first**, then SQLite. A vector failure therefore never
   exposes restored SQLite rows against old vectors.
5. On any failure, both stores are rolled back from the saved copies; rollback
   errors are reported and the staged files are kept for manual recovery.

Stop ingestion and connector polling before restoring; restart the application
afterwards so caches and schedulers reload.

## Retention of audit data

`BLACK_ONYX_AUDIT_RETENTION_DAYS` (default `365`, `0` keeps all) prunes
`audit_events` older than the window whenever background schedulers start
(startup and after a settings save).

## Verification

`tests/test_backup.py` covers the SQLite round trip and a Qdrant restore
failure that rolls both stores back; `tests/test_backup_security.py` covers
archive validation. Run `uv run pytest tests -q -k backup`.
The automated suite covers archive validation, restore round trips, and
rollback after a Qdrant failure. Validate restore time, capacity, and recovery
procedures against a representative staging backup before production use.
