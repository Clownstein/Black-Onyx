"""Gateway challenge tools use the registered adapter and single-use approval."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

GATEWAY_ROOT = Path(__file__).resolve().parents[1] / "services" / "security-gateway"
if str(GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(GATEWAY_ROOT))

from black_onyx.auth.service import Principal, Role


@pytest.mark.asyncio
async def test_challenge_dispatch_is_actor_scoped_and_admin_approved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-challenge-dispatch-secret")
    monkeypatch.setenv("SECURITY_GATEWAY_KEY", "test-gateway-key-with-at-least-32-characters")
    monkeypatch.setenv("SECURITY_APPROVAL_DB", str(tmp_path / "approvals.sqlite3"))
    monkeypatch.setenv("SECURITY_CHALLENGE_DB", str(tmp_path / "challenges.sqlite3"))

    from black_onyx.api.routes_security import _security_token
    from security_gateway import app as gateway

    monkeypatch.setattr(gateway, "_refresh_attestation", AsyncMock())
    monkeypatch.setattr(gateway, "_refresh_egress_readiness", AsyncMock())
    monkeypatch.setattr(gateway, "_refresh_shodan_readiness", AsyncMock())
    monkeypatch.setattr(gateway, "_refresh_capture_readiness", AsyncMock())

    def auth(user_id: str, role: Role) -> dict[str, str]:
        principal = Principal(user_id, f"{user_id}@test", user_id, role)
        return {"Authorization": f"Bearer {_security_token(principal)}"}

    analyst = auth("analyst-1", Role.ANALYST)
    admin = auth("admin-1", Role.ADMIN)
    transport = ASGITransport(app=gateway.app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        initial = await client.post(
            "/v1/tools/check_solved", headers=analyst,
            json={"arguments": {"challenge_id": "reference-basic"}},
        )
        assert initial.status_code == 200
        assert json.loads(initial.json()["output"])["solved"] is False

        request_body = {
            "arguments": {"challenge_id": "reference-basic", "solution": "flag{black_onyx_reference}"},
            "session_id": "lab", "timeout": 30, "network_profile": "offline", "destinations": [],
        }
        preview = await client.post(
            "/v1/tools/submit_solution/preview", headers=analyst, json=request_body,
        )
        assert preview.status_code == 200, preview.text
        approved_body = {**preview.json(), "requester": "analyst-1"}
        approval = await client.post(
            "/v1/tools/submit_solution/approve", headers=admin, json=approved_body,
        )
        assert approval.status_code == 200, approval.text
        execution_body = {
            **request_body,
            **{key: preview.json()[key] for key in (
                "network_profile", "destinations", "ports", "lab_profile_id", "resolved_targets",
            )},
            "approval_id": approval.json()["approval_id"],
        }
        submitted = await client.post(
            "/v1/tools/submit_solution", headers=analyst, json=execution_body,
        )
        assert submitted.status_code == 200, submitted.text
        assert json.loads(submitted.json()["output"])["accepted"] is True
        solved = await client.post(
            "/v1/tools/check_solved", headers=analyst,
            json={"arguments": {"challenge_id": "reference-basic"}},
        )
        assert json.loads(solved.json()["output"])["solved"] is True

        replay = await client.post(
            "/v1/tools/submit_solution", headers=analyst, json=execution_body,
        )
        assert replay.status_code == 403
