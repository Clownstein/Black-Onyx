from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, text

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "migration" / "retention_job.py"
_spec = importlib.util.spec_from_file_location("retention_job_mod", _PATH)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
sys.modules["retention_job_mod"] = _mod
_spec.loader.exec_module(_mod)
RetentionDefaults = _mod.RetentionDefaults
run_retention = _mod.run_retention


def test_retention_archives_and_deletes_old_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "retention.db"
    url = f"sqlite+pysqlite:///{db_path.as_posix()}"
    engine = create_engine(url)
    now = datetime(2026, 7, 26, tzinfo=UTC)
    old = (now - timedelta(days=40)).isoformat().replace("+00:00", "Z")
    recent = (now - timedelta(days=2)).isoformat().replace("+00:00", "Z")

    run_retention(url, defaults=RetentionDefaults(normalized_logs_days=30), dry_run=True, now=now)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO normalized_logs (created_at, payload) VALUES (:c, :p)"),
            [{"c": old, "p": "old"}, {"c": recent, "p": "new"}],
        )

    report = run_retention(
        url,
        defaults=RetentionDefaults(normalized_logs_days=30),
        archive=True,
        dry_run=False,
        now=now,
    )
    actions = {a["table"]: a for a in report["actions"]}
    assert actions["normalized_logs"]["deleted"] == 1

    with engine.connect() as conn:
        remaining = conn.execute(text("SELECT payload FROM normalized_logs")).scalars().all()
        archived = conn.execute(text("SELECT COUNT(*) FROM retention_archive")).scalar_one()
    assert remaining == ["new"]
    assert archived == 1
