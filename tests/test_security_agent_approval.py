"""Agent pause-for-approval, resume, replay and two-person approval in the gateway."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

GATEWAY_ROOT = Path(__file__).resolve().parents[1] / "services" / "security-gateway"
if str(GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(GATEWAY_ROOT))

from black_onyx.auth.service import Principal, Role  # noqa: E402

WRITE_CALL = '<|tool_call>call:Write:c1{"path":"a.txt","content":"x"}<tool_call|>'


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-for-agent-approval")
    monkeypatch.setenv("SECURITY_GATEWAY_KEY", "test-gateway-key-with-at-least-32-characters")
    monkeypatch.setenv("SECURITY_RUNNER_TOKEN", "test-runner-token")
    monkeypatch.setenv("SECURITY_APPROVAL_DB", str(tmp_path / "approvals.db"))


def _auth(user_id: str = "u-analyst", role: Role = Role.ANALYST) -> dict[str, str]:
    from black_onyx.api.routes_security import _security_token

    return {"Authorization": f"Bearer {_security_token(Principal(user_id, f'{user_id}@test', user_id, role))}"}


class ScriptedLLM:
    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)

    async def chat(self, **_kwargs: Any):
        from security_gateway.llm_client import GenerateResult

        return GenerateResult(content=self.replies.pop(0), usage={})


async def _client():
    from security_gateway.app import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_agent_pauses_then_resumes_with_single_use_approval() -> None:
    from security_gateway import app as gateway

    dispatched: list[dict[str, Any]] = []

    async def fake_dispatch(self, tool_name, arguments, session_id, authorization=None, *, approval_id=None, request_body=None):
        dispatched.append({"tool": tool_name, "approval_id": approval_id, "session_id": session_id})
        return {"status": "success", "output": "written"}

    llm = ScriptedLLM([WRITE_CALL, "done writing"])
    with patch.object(gateway._agent_loop, "_llm", llm), \
         patch("security_gateway.app._ensure_workspace", new_callable=AsyncMock), \
         patch("security_gateway.app._tool_status", lambda _name: "enabled"), \
         patch.object(type(gateway._agent_loop), "_dispatch_tool", fake_dispatch):
        async with await _client() as client:
            started = await client.post("/v1/agent/run", headers=_auth(), json={"message": "write it", "session_id": "lab"})
            assert started.status_code == 200, started.json()
            body = started.json()
            assert body["status"] == "pending_approval"
            assert dispatched == []  # nothing ran before approval
            pending = body["pending_approval"]
            assert pending["tool"] == "Write"

            # Another user cannot see or resume the run.
            assert (await client.get(f"/v1/agent/runs/{body['run_id']}", headers=_auth("u-other"))).status_code == 404
            other = await client.post(f"/v1/agent/runs/{body['run_id']}/resume", headers=_auth("u-other"),
                                      json={"approval_id": "x"})
            assert other.status_code == 409

            approval = await client.post("/v1/tools/Write/approve", headers=_auth(), json={
                "arguments": pending["arguments"], "session_id": pending["session_id"],
                "timeout": pending["timeout"], "preview_hash": pending["preview_hash"],
            })
            assert approval.status_code == 200, approval.json()
            approval_id = approval.json()["approval_id"]

            resumed = await client.post(f"/v1/agent/runs/{body['run_id']}/resume", headers=_auth(),
                                        json={"approval_id": approval_id})
            assert resumed.status_code == 200, resumed.json()
            assert resumed.json()["status"] == "ok"
            assert resumed.json()["answer"] == "done writing"
            assert dispatched == [{"tool": "Write", "approval_id": approval_id, "session_id": "lab"}]

            replay = await client.post(f"/v1/agent/runs/{body['run_id']}/resume", headers=_auth(),
                                       json={"approval_id": approval_id})
            assert replay.status_code == 409


@pytest.mark.asyncio
async def test_agent_rewrites_run_binary_nikto_and_pins_public_preview() -> None:
    from security_gateway import app as gateway

    nikto_call = '<|tool_call>call:run_binary:c1{"path":"nikto","args":"http://sec.dw.style"}<tool_call|>'
    llm = ScriptedLLM([nikto_call, "scan complete"])
    dispatched: list[dict[str, Any]] = []

    async def fake_dispatch(self, tool_name, arguments, session_id, authorization=None, *, approval_id=None, request_body=None):
        dispatched.append({
            "tool": tool_name, "approval_id": approval_id, "arguments": arguments,
            "request_body": request_body,
        })
        return {"status": "success", "output": "nikto findings"}

    async def fake_resolve(profile, destinations, ports, lab_profile_id):
        assert profile == "public"
        assert destinations == ["sec.dw.style"]
        assert ports == [80]
        return {"sec.dw.style": ["203.0.113.10"]}

    with patch.object(gateway._agent_loop, "_llm", llm), \
         patch("security_gateway.app._ensure_workspace", new_callable=AsyncMock), \
         patch("security_gateway.app._tool_status", lambda _name: "enabled"), \
         patch("security_gateway.app._env_flag", lambda _name: True), \
         patch("security_gateway.app._egress_configured", lambda: True), \
         patch("security_gateway.app._resolve_preview_targets", fake_resolve), \
         patch.object(type(gateway._agent_loop), "_dispatch_tool", fake_dispatch):
        async with await _client() as client:
            started = await client.post(
                "/v1/agent/run", headers=_auth(),
                json={"message": "scan it", "session_id": "lab"},
            )
            assert started.status_code == 200, started.text
            body = started.json()
            assert body["status"] == "pending_approval"
            pending = body["pending_approval"]
            assert pending["tool"] == "nikto_scan"
            assert pending["arguments"]["target"] == "http://sec.dw.style"
            assert pending["network_profile"] == "public"
            assert pending["destinations"] == ["sec.dw.style"]
            assert pending["ports"] == [80]
            assert pending["resolved_targets"] == {"sec.dw.style": ["203.0.113.10"]}
            assert dispatched == []

            status = await client.get(f"/v1/agent/runs/{body['run_id']}", headers=_auth())
            assert status.json()["pending_approval"]["resolved_targets"] == {
                "sec.dw.style": ["203.0.113.10"],
            }

            approval = await client.post("/v1/tools/nikto_scan/approve", headers=_auth(), json={
                "arguments": pending["arguments"],
                "session_id": pending["session_id"],
                "timeout": pending["timeout"],
                "network_profile": pending["network_profile"],
                "destinations": pending["destinations"],
                "ports": pending["ports"],
                "resolved_targets": pending["resolved_targets"],
                "preview_hash": pending["preview_hash"],
            })
            assert approval.status_code == 200, approval.text
            resumed = await client.post(
                f"/v1/agent/runs/{body['run_id']}/resume",
                headers=_auth(),
                json={"approval_id": approval.json()["approval_id"]},
            )
            assert resumed.status_code == 200, resumed.text
            assert dispatched[0]["tool"] == "nikto_scan"
            assert dispatched[0]["request_body"]["resolved_targets"] == {
                "sec.dw.style": ["203.0.113.10"],
            }


@pytest.mark.asyncio
async def test_agent_rewrites_bash_whoami_to_workspace_run_binary() -> None:
    from security_gateway import app as gateway

    whoami_call = '<|tool_call>call:run_binary:c1{"path":"/bin/bash","args":"whoami"}<tool_call|>'
    llm = ScriptedLLM([whoami_call, "sandbox user toolbox"])
    dispatched: list[dict[str, Any]] = []

    async def fake_dispatch(self, tool_name, arguments, session_id, authorization=None, *, approval_id=None, request_body=None):
        dispatched.append({"tool": tool_name, "arguments": arguments, "approval_id": approval_id})
        return {"status": "success", "output": "toolbox"}

    with patch.object(gateway._agent_loop, "_llm", llm), \
         patch("security_gateway.app._ensure_workspace", new_callable=AsyncMock), \
         patch("security_gateway.app._tool_status", lambda _name: "enabled"), \
         patch.object(type(gateway._agent_loop), "_dispatch_tool", fake_dispatch):
        async with await _client() as client:
            headers = _auth("u-admin", Role.ADMIN)
            started = await client.post("/v1/agent/run", headers=headers, json={"message": "whoami", "session_id": "lab"})
            assert started.status_code == 200, started.text
            body = started.json()
            assert body["status"] == "pending_approval"
            pending = body["pending_approval"]
            assert pending["tool"] == "run_binary"
            assert pending["arguments"] == {"path": "whoami"}
            approval = await client.post("/v1/tools/run_binary/approve", headers=headers, json={
                "arguments": pending["arguments"], "session_id": pending["session_id"],
                "timeout": pending["timeout"], "preview_hash": pending["preview_hash"],
                "network_profile": pending["network_profile"],
                "destinations": pending["destinations"],
                "ports": pending["ports"],
                "resolved_targets": pending["resolved_targets"],
            })
            assert approval.status_code == 200, approval.text
            approval_id = approval.json()["approval_id"]
            resumed = await client.post(
                f"/v1/agent/runs/{body['run_id']}/resume",
                headers=headers,
                json={"approval_id": approval_id},
            )
            assert resumed.status_code == 200, resumed.text
            assert resumed.json()["status"] == "ok"
            assert dispatched == [{"tool": "run_binary", "arguments": {"path": "whoami"}, "approval_id": approval_id}]


@pytest.mark.asyncio
async def test_agent_denial_is_reported_to_the_model() -> None:
    from security_gateway import app as gateway

    llm = ScriptedLLM([WRITE_CALL, "understood, not writing"])
    with patch.object(gateway._agent_loop, "_llm", llm), \
         patch("security_gateway.app._ensure_workspace", new_callable=AsyncMock), \
         patch("security_gateway.app._tool_status", lambda _name: "enabled"):
        async with await _client() as client:
            run = (await client.post("/v1/agent/run", headers=_auth(), json={"message": "write"})).json()
            denied = await client.post(f"/v1/agent/runs/{run['run_id']}/resume", headers=_auth(), json={"deny": True})
    assert denied.status_code == 200
    row = denied.json()["tool_results"][-1]
    assert row["result"]["denied"] is True
    assert row["status"] == "error"
    assert "denied" in str(row["error"] or row["summary"]).lower() or row["result"]["denied"] is True


@pytest.mark.asyncio
async def test_viewer_cannot_run_agent() -> None:
    async with await _client() as client:
        response = await client.post("/v1/agent/run", headers=_auth("u-viewer", Role.VIEWER), json={"message": "x"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_two_person_tiers_require_a_different_administrator(monkeypatch: pytest.MonkeyPatch) -> None:
    from security_gateway.approvals import request_digest

    monkeypatch.setenv("SECURITY_TWO_PERSON_TIERS", "workspace-write")
    body = {"arguments": {"path": "a.txt", "content": "x"}, "session_id": "lab", "timeout": 30}
    with patch("security_gateway.app._tool_status", lambda _name: "enabled"):
        async with await _client() as client:
            own = await client.post("/v1/tools/Write/approve", headers=_auth("u-admin", Role.ADMIN), json={
                **body, "preview_hash": request_digest("u-admin", "Write", body),
            })
            assert own.status_code == 403
            analyst_for_other = await client.post("/v1/tools/Write/approve", headers=_auth("u-analyst"), json={
                **body, "requester": "u-admin", "preview_hash": request_digest("u-admin", "Write", body),
            })
            assert analyst_for_other.status_code == 403
            second = await client.post("/v1/tools/Write/approve", headers=_auth("u-admin2", Role.ADMIN), json={
                **body, "requester": "u-analyst", "preview_hash": request_digest("u-analyst", "Write", body),
            })
            assert second.status_code == 200, second.json()


def test_approval_store_migrates_legacy_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from security_gateway import approvals

    legacy = tmp_path / "legacy.db"
    connection = sqlite3.connect(legacy)
    connection.execute("""CREATE TABLE approvals (
        approval_id TEXT PRIMARY KEY, principal TEXT NOT NULL, tool TEXT NOT NULL,
        request_digest TEXT NOT NULL, policy_version INTEGER NOT NULL, approved_by TEXT NOT NULL,
        expires_at INTEGER NOT NULL, used_at INTEGER)""")
    connection.commit()
    connection.close()
    monkeypatch.setenv("SECURITY_APPROVAL_DB", str(legacy))
    body = {"arguments": {}, "session_id": "lab"}
    approval_id = approvals.approve("p", "Write", body, "p")
    assert approvals.consume(approval_id, "p", "Write", body)
    versions = [row[0] for row in sqlite3.connect(legacy).execute("SELECT version FROM schema_migrations")]
    assert versions == list(range(1, approvals.SCHEMA_VERSION + 1))


@pytest.mark.asyncio
async def test_cancel_targets_only_the_callers_session() -> None:
    import hashlib

    seen: dict[str, Any] = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"status": "cancelling"}

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def post(self, url, headers, json):
            seen.update(url=url, body=json)
            return FakeResponse()

    with patch("security_gateway.app.httpx.AsyncClient", FakeClient):
        async with await _client() as client:
            ok = await client.post("/v1/tools/jobs/job-abcdefgh/cancel", headers=_auth(), json={"session_id": "lab"})
            bad = await client.post("/v1/tools/jobs/..%2f/cancel", headers=_auth(), json={"session_id": "lab"})
            viewer = await client.post("/v1/tools/jobs/job-abcdefgh/cancel", headers=_auth("v", Role.VIEWER),
                                       json={"session_id": "lab"})
    assert ok.status_code == 200
    assert seen["url"].endswith("/jobs/job-abcdefgh/cancel")
    assert seen["body"] == {"session": f"{hashlib.sha256(b'u-analyst').hexdigest()}/lab"}
    assert bad.status_code in (400, 404)
    assert viewer.status_code == 403
