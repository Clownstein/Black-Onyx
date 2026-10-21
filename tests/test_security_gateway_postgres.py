"""security-gateway approval/agent-run/challenge state on real Postgres.

Runs only when BLACK_ONYX_TEST_DATABASE_URL points at a disposable Postgres; a
sibling ``<db>_gateway`` database is created so the gateway's Alembic history
never collides with the platform's.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest

GATEWAY_ROOT = Path(__file__).resolve().parents[1] / "services" / "security-gateway"
if str(GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(GATEWAY_ROOT))

_BASE_URL = os.environ.get("BLACK_ONYX_TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not _BASE_URL, reason="Set BLACK_ONYX_TEST_DATABASE_URL for integration test"
)


@pytest.fixture(scope="module")
def gateway_url() -> str:
    import psycopg
    from psycopg import sql

    parts = urlsplit(_BASE_URL)
    name = parts.path.lstrip("/") + "_gateway"
    admin = urlunsplit(parts._replace(path="/postgres")).replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    return urlunsplit(parts._replace(path=f"/{name}"))


@pytest.fixture
def gateway_db(gateway_url: str, monkeypatch: pytest.MonkeyPatch):
    from alembic import command
    from alembic.config import Config

    from security_gateway.db import reset_gateway_engine_for_tests

    monkeypatch.setenv("SECURITY_GATEWAY_DATABASE_URL", gateway_url)
    monkeypatch.setenv("SECURITY_GATEWAY_KEY", "k" * 48)
    monkeypatch.chdir(GATEWAY_ROOT)
    command.upgrade(Config(str(GATEWAY_ROOT / "alembic.ini")), "head")
    reset_gateway_engine_for_tests()
    yield gateway_url
    reset_gateway_engine_for_tests()


def test_approval_is_single_use_and_bound_to_request(gateway_db) -> None:
    from security_gateway import approvals

    body = {"target": "10.88.0.10", "ports": "80"}
    approval_id = approvals.approve("alice", "nmap_scan", body, "bob")
    assert not approvals.consume(approval_id, "alice", "nmap_scan", {"target": "10.88.0.11"})
    assert not approvals.consume(approval_id, "mallory", "nmap_scan", body)
    assert approvals.consume(approval_id, "alice", "nmap_scan", body)
    assert not approvals.consume(approval_id, "alice", "nmap_scan", body)


def test_agent_run_resumes_once_and_is_principal_scoped(gateway_db) -> None:
    from security_gateway import approvals

    state = {"pending_call": {"tool": "hydra"}, "messages": [{"role": "user", "content": "50% done?"}]}
    run_id = approvals.save_agent_run("alice", state, "hydra", "digest-1")
    assert approvals.get_agent_run(run_id, "mallory") is None
    assert approvals.get_agent_run(run_id, "alice")["status"] == "pending_approval"
    # Another principal cannot overwrite the run via upsert.
    approvals.save_agent_run("mallory", {"x": 1}, "nmap_scan", "digest-2", run_id=run_id)
    claimed = approvals.claim_agent_run(run_id, "alice")
    assert claimed is not None and claimed["pending_tool"] == "hydra"
    assert claimed["messages"][0]["content"] == "50% done?"
    assert approvals.claim_agent_run(run_id, "alice") is None
    approvals.finish_agent_run(run_id, "completed")
    assert approvals.get_agent_run(run_id, "alice")["status"] == "completed"


def test_reference_challenge_solve_is_idempotent_and_ready(gateway_db) -> None:
    from security_gateway import challenge_adapter
    from security_gateway.db import gateway_ready

    actor = "alice"
    assert challenge_adapter._submit_reference(actor, "wrong")["accepted"] is False
    assert challenge_adapter._reference_status(actor)["solved"] is False
    answer = challenge_adapter.REFERENCE_ANSWER
    assert challenge_adapter._submit_reference(actor, answer)["accepted"] is True
    assert challenge_adapter._submit_reference(actor, answer)["accepted"] is True
    assert challenge_adapter._reference_status(actor)["solved"] is True
    assert gateway_ready() is True
    assert challenge_adapter.ready() is True


def test_readiness_is_false_not_an_error_when_database_is_unreachable(monkeypatch) -> None:
    from security_gateway import challenge_adapter
    from security_gateway.db import gateway_ready, reset_gateway_engine_for_tests

    monkeypatch.setenv(
        "SECURITY_GATEWAY_DATABASE_URL", "postgresql+psycopg://nobody:x@127.0.0.1:1/none"
    )
    reset_gateway_engine_for_tests()
    try:
        assert gateway_ready() is False
        assert challenge_adapter.ready() is False
    finally:
        reset_gateway_engine_for_tests()

