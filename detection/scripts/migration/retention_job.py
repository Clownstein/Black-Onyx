#!/usr/bin/env python3
"""Delete/archive rows older than platform §14.8 retention defaults."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine


@dataclass(frozen=True)
class RetentionDefaults:
    """Platform §14.8 defaults (days)."""

    raw_logs_days: int = 14
    normalized_logs_days: int = 30
    log_templates_and_features_days: int = 90
    raw_flow_metadata_days: int = 30
    aggregated_network_features_days: int = 180
    raw_metric_samples_days: int = 30
    downsampled_metrics_days: int = 365
    code_findings_days: int = 90
    incidents_and_audit_days: int = 365
    operational_history_days: int = 365
    drift_observations_days: int = 365
    response_audit_days: int = 365
    notification_delivery_days: int = 90


TABLE_POLICY: dict[str, str] = {
    "raw_logs": "raw_logs_days",
    "normalized_logs": "normalized_logs_days",
    "log_templates": "log_templates_and_features_days",
    "log_features": "log_templates_and_features_days",
    "raw_flow_metadata": "raw_flow_metadata_days",
    "aggregated_network_features": "aggregated_network_features_days",
    "raw_metric_samples": "raw_metric_samples_days",
    "downsampled_metrics": "downsampled_metrics_days",
    "code_findings": "code_findings_days",
    "incidents": "incidents_and_audit_days",
    "audit_records": "incidents_and_audit_days",
    "incident_timeline": "operational_history_days",
    "analyst_feedback": "operational_history_days",
    "operational_audit": "operational_history_days",
    "deployment_events": "operational_history_days",
    "response_audit": "response_audit_days",
    "response_requests": "response_audit_days",
    "drift_observations": "drift_observations_days",
    "email_outbox": "notification_delivery_days",
}

TABLE_TIMESTAMP_COLUMN: dict[str, str] = {
    "incident_timeline": "occurred_at",
    "deployment_events": "deployed_at",
    "drift_observations": "observed_at",
    "email_outbox": "updated_at",
}

# Compatibility aliases used by simpler env-driven schedules.
DEFAULTS = {
    "RAW_LOGS_DAYS": 14,
    "NORMALIZED_LOGS_DAYS": 30,
    "NETWORK_FLOWS_DAYS": 30,
    "RAW_METRICS_DAYS": 30,
    "INCIDENTS_DAYS": 365,
}


def load_defaults_from_env() -> RetentionDefaults:
    base = RetentionDefaults()
    values: dict[str, int] = {}
    for field_name in asdict(base):
        env_key = f"RETENTION_{field_name.upper()}"
        if env_key in os.environ:
            values[field_name] = int(os.environ[env_key])
    return RetentionDefaults(**{**asdict(base), **values})


def retention_cutoff(env_key: str) -> datetime:
    days = int(os.getenv(env_key, str(DEFAULTS[env_key])))
    return datetime.now(UTC) - timedelta(days=days)


def plan_deletions() -> dict[str, str]:
    return {key: retention_cutoff(key).isoformat() for key in DEFAULTS}


def cutoff_for(days: int, *, now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now - timedelta(days=days)


def _ensure_schema(engine: Engine) -> None:
    dialect = engine.dialect.name
    # Only bootstrap synthetic tables for the SQLite integration test harness.
    # Deployable databases are owned by their service Alembic migrations.
    if dialect != "sqlite":
        return
    if dialect == "sqlite":
        id_type = "INTEGER PRIMARY KEY AUTOINCREMENT"
    else:
        id_type = "BIGSERIAL PRIMARY KEY"

    statements = [
        f"""
        CREATE TABLE IF NOT EXISTS retention_archive (
            id {id_type},
            source_table TEXT NOT NULL,
            row_payload TEXT NOT NULL,
            archived_at TEXT NOT NULL
        )
        """
    ]
    for table in TABLE_POLICY:
        timestamp_column = TABLE_TIMESTAMP_COLUMN.get(table, "created_at")
        statements.append(
            f"""
            CREATE TABLE IF NOT EXISTS {table} (
                id {id_type},
                {timestamp_column} TEXT NOT NULL,
                payload TEXT
            )
            """
        )
    with engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))


def run_retention(
    database_url: str,
    *,
    defaults: RetentionDefaults | None = None,
    archive: bool = True,
    dry_run: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    defaults = defaults or load_defaults_from_env()
    engine = create_engine(database_url)
    _ensure_schema(engine)
    available_tables = set(inspect(engine).get_table_names())
    report: dict[str, Any] = {
        "dry_run": dry_run,
        "archive": archive,
        "cutoffs": {},
        "actions": [],
    }

    with engine.begin() as conn:
        for table, policy_field in TABLE_POLICY.items():
            if table not in available_tables:
                report["actions"].append(
                    {"table": table, "status": "skipped", "reason": "table_not_present"}
                )
                continue
            days = int(getattr(defaults, policy_field))
            cutoff = cutoff_for(days, now=now)
            cutoff_iso = cutoff.isoformat().replace("+00:00", "Z")
            report["cutoffs"][table] = {"days": days, "cutoff": cutoff_iso}
            timestamp_column = TABLE_TIMESTAMP_COLUMN.get(table, "created_at")

            rows = (
                conn.execute(
                    text(f"SELECT * FROM {table} WHERE {timestamp_column} < :cutoff"),
                    {"cutoff": cutoff_iso},
                )
                .mappings()
                .all()
            )
            if dry_run:
                report["actions"].append(
                    {
                        "table": table,
                        "would_delete": len(rows),
                        "would_archive": len(rows) if archive else 0,
                    }
                )
                continue

            for row in rows:
                if archive:
                    conn.execute(
                        text(
                            """
                            INSERT INTO retention_archive (source_table, row_payload, archived_at)
                            VALUES (:source_table, :row_payload, :archived_at)
                            """
                        ),
                        {
                            "source_table": table,
                            "row_payload": json.dumps(dict(row), default=str),
                            "archived_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        },
                    )
                conn.execute(text(f"DELETE FROM {table} WHERE id = :id"), {"id": row["id"]})
            report["actions"].append(
                {"table": table, "deleted": len(rows), "archived": len(rows) if archive else 0}
            )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=os.environ.get("RETENTION_DATABASE_URL", "sqlite+pysqlite:///./retention.db"),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-archive", action="store_true")
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Print simple cutoffs from DEFAULTS env keys and exit",
    )
    args = parser.parse_args(argv)
    if args.plan_only:
        for table, cutoff in plan_deletions().items():
            print(f"{table}: delete before {cutoff}")
        return 0
    report = run_retention(
        args.database_url,
        archive=not args.no_archive,
        dry_run=args.dry_run,
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
