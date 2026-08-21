"""Apply one service's Alembic head and compare it with SQLAlchemy metadata.

Run this in a fresh process with the service directory first on ``PYTHONPATH``.
That isolation prevents cross-service imports while preserving each service's
unique package name.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
import tempfile
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

DATABASE_ENV = {
    "asset-registry": "ASSET_REGISTRY_DATABASE_URL",
    "incident-api": "INCIDENT_API_DATABASE_URL",
    "response-orchestrator": "RESPONSE_ORCHESTRATOR_DATABASE_URL",
    "integration-hub": "INTEGRATION_HUB_DATABASE_URL",
    "training-orchestrator": "TRAINING_ORCHESTRATOR_DATABASE_URL",
    "threat-intel-service": "THREAT_INTEL_DATABASE_URL",
    "notification-service": "NOTIFICATION_DATABASE_URL",
    "smoke-consumer": "SMOKE_DATABASE_URL",
}


def _foreign_keys(inspector, table: str) -> set[tuple[tuple[str, ...], str, tuple[str, ...]]]:
    return {
        (
            tuple(fk.get("constrained_columns") or ()),
            str(fk.get("referred_table") or ""),
            tuple(fk.get("referred_columns") or ()),
        )
        for fk in inspector.get_foreign_keys(table)
    }


def check(service_dir: Path) -> list[str]:
    service_name = service_dir.name
    env_name = DATABASE_ENV.get(service_name)
    if env_name is None:
        return [f"unsupported stateful service: {service_name}"]
    alembic_ini = service_dir / "alembic.ini"
    if not alembic_ini.is_file():
        return [f"missing Alembic config: {alembic_ini}"]

    with tempfile.TemporaryDirectory(prefix=f"aa-migration-{service_name}-") as tmp:
        database_path = Path(tmp) / "parity.db"
        database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
        os.environ[env_name] = database_url
        os.environ.pop("DATABASE_URL", None)

        sys.path.insert(0, str(service_dir))
        importlib.invalidate_caches()
        package = service_name.replace("-", "_")
        db_module = importlib.import_module(f"{package}.db")
        try:
            importlib.import_module(f"{package}.models")
        except ModuleNotFoundError as exc:
            if exc.name != f"{package}.models":
                raise
        metadata = db_module.Base.metadata

        config = Config(str(alembic_ini))
        config.set_main_option("script_location", str(service_dir / "alembic"))
        config.set_main_option("sqlalchemy.url", database_url)
        command.upgrade(config, "head")

        engine = create_engine(database_url)
        inspector = inspect(engine)
        actual_tables = set(inspector.get_table_names()) - {"alembic_version"}
        expected_tables = set(metadata.tables)
        errors: list[str] = []
        if missing := expected_tables - actual_tables:
            errors.append(f"missing tables: {sorted(missing)}")
        if extra := actual_tables - expected_tables:
            errors.append(f"unmanaged tables: {sorted(extra)}")

        for table in sorted(expected_tables & actual_tables):
            expected_columns = set(metadata.tables[table].columns.keys())
            actual_columns = {column["name"] for column in inspector.get_columns(table)}
            if missing_columns := expected_columns - actual_columns:
                errors.append(f"{table}: missing columns {sorted(missing_columns)}")
            if extra_columns := actual_columns - expected_columns:
                errors.append(f"{table}: unmanaged columns {sorted(extra_columns)}")

            actual_column_rows = {column["name"]: column for column in inspector.get_columns(table)}
            for column in metadata.tables[table].columns:
                actual = actual_column_rows.get(column.name)
                if actual is not None and bool(actual.get("nullable")) != bool(column.nullable):
                    errors.append(
                        f"{table}.{column.name}: nullable={actual.get('nullable')} "
                        f"but model expects {column.nullable}"
                    )

            expected_fks = {
                (
                    tuple(element.parent.name for element in constraint.elements),
                    constraint.referred_table.name,
                    tuple(element.column.name for element in constraint.elements),
                )
                for constraint in metadata.tables[table].foreign_key_constraints
            }
            actual_fks = _foreign_keys(inspector, table)
            if missing_fks := expected_fks - actual_fks:
                errors.append(f"{table}: missing foreign keys {sorted(missing_fks)}")

            expected_indexes = {
                (tuple(column.name for column in index.columns), bool(index.unique))
                for index in metadata.tables[table].indexes
            }
            actual_indexes = {
                (tuple(index.get("column_names") or ()), bool(index.get("unique")))
                for index in inspector.get_indexes(table)
            }
            if missing_indexes := expected_indexes - actual_indexes:
                errors.append(f"{table}: missing indexes {sorted(missing_indexes)}")

            expected_uniques = {
                tuple(column.name for column in constraint.columns)
                for constraint in metadata.tables[table].constraints
                if constraint.__class__.__name__ == "UniqueConstraint"
            }
            actual_uniques = {
                tuple(item.get("column_names") or ())
                for item in inspector.get_unique_constraints(table)
            }
            if missing_uniques := expected_uniques - actual_uniques:
                errors.append(f"{table}: missing unique constraints {sorted(missing_uniques)}")
        engine.dispose()
        return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True, type=Path)
    args = parser.parse_args()
    service_dir = args.service.resolve()
    errors = check(service_dir)
    if errors:
        for error in errors:
            print(f"ERROR {service_dir.name}: {error}")
        return 1
    print(f"OK {service_dir.name}: Alembic head matches SQLAlchemy metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
