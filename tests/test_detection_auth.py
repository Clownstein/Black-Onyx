"""Tests for detection-plane JWT minting (Black Onyx → detection-plane APIs)."""

import os

import pytest

from black_onyx.detection_auth import mint_detection_token


@pytest.fixture(autouse=True)
def _auth_secret(monkeypatch):
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-for-detection-jwt-minting-ok")
    monkeypatch.delenv("BLACK_ONYX_DETECTION_JWT_SECRET", raising=False)
    monkeypatch.delenv("OIDC_HS_SECRET", raising=False)


def test_mint_detection_token_is_three_segments():
    token = mint_detection_token(subject="analyst@example.com", role="analyst", tenant_id="tenant-a")
    assert token.count(".") == 2
    assert len(token) > 40


def test_mint_maps_admin_role():
    token = mint_detection_token(subject="admin@example.com", role="admin", tenant_id="tenant-a")
    # payload is middle segment; decode without verify for shape check
    import base64
    import json

    payload_b64 = token.split(".")[1]
    pad = "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
    assert payload["tenant_id"] == "tenant-a"
    assert "admin" in payload["roles"]
    assert payload["sub"] == "admin@example.com"


def test_mint_maps_viewer_role_not_admin():
    import base64
    import json

    token = mint_detection_token(subject="viewer@example.com", role="viewer", tenant_id="tenant-a")
    payload_b64 = token.split(".")[1]
    pad = "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
    assert payload["roles"] == ["viewer"]
    assert "admin" not in payload["roles"]


def test_mint_uses_pyjwt_roundtrip(monkeypatch):
    import jwt as pyjwt

    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "roundtrip-secret-for-pyjwt-tests")
    token = mint_detection_token(subject="a@b.c", role="analyst", tenant_id="t1")
    claims = pyjwt.decode(token, "roundtrip-secret-for-pyjwt-tests", algorithms=["HS256"])
    assert claims["sub"] == "a@b.c"
    assert claims["tenant_id"] == "t1"
    assert "analyst" in claims["roles"]


def test_detection_bff_mutations_require_analyst(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from black_onyx.api.routes_detection import detection_router
    from black_onyx.auth.service import Principal, Role

    app = FastAPI()
    app.include_router(detection_router)

    @app.middleware("http")
    async def inject_viewer(request, call_next):
        request.state.principal = Principal(
            user_id="u1",
            email="viewer@example.com",
            display_name="Viewer",
            role=Role.VIEWER,
        )
        return await call_next(request)

    client = TestClient(app)
    assert client.get("/api/v1/detection/health").status_code == 200
    resp = client.post("/api/v1/detection/incident/api/v1/incidents/x/disposition", json={})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_detection_proxy_rejects_path_traversal():
    """F08: BFF rejects ../ and // proxy paths with 400."""
    from fastapi import HTTPException
    from starlette.requests import Request

    from black_onyx.api.routes_detection import _proxy
    from black_onyx.auth.service import Principal, Role

    user = Principal(
        user_id="u-path",
        email="analyst@example.com",
        display_name="Analyst",
        role=Role.ANALYST,
    )

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "client": ("test", 1),
            "server": ("test", 80),
        },
        receive,
    )

    with pytest.raises(HTTPException) as trav:
        await _proxy(
            request,
            upstream="incident",
            path="api/v1/../secrets",
            user=user,
        )
    assert trav.value.status_code == 400
    assert "Invalid detection proxy path" in str(trav.value.detail)

    with pytest.raises(HTTPException) as doubled:
        await _proxy(
            request,
            upstream="incident",
            path="api/v1//incidents",
            user=user,
        )
    assert doubled.value.status_code == 400
    assert "Invalid detection proxy path" in str(doubled.value.detail)


def test_detection_token_endpoint_gone():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from black_onyx.api.routes_detection import detection_router
    from black_onyx.auth.service import Principal, Role

    app = FastAPI()
    app.include_router(detection_router)

    @app.middleware("http")
    async def inject_analyst(request, call_next):
        request.state.principal = Principal(
            user_id="u2",
            email="analyst@example.com",
            display_name="Analyst",
            role=Role.ANALYST,
        )
        return await call_next(request)

    client = TestClient(app)
    resp = client.post("/api/v1/auth/detection-token")
    assert resp.status_code == 410


def test_inject_actor_overwrites_spoofed_actor():
    from black_onyx.api.routes_detection import _inject_actor
    from black_onyx.auth.service import Principal, Role

    user = Principal(
        user_id="u3",
        email="alice@onyx.local",
        display_name="Alice",
        role=Role.ANALYST,
    )
    out = _inject_actor(
        "api/v1/incidents/inc-1/disposition",
        "POST",
        b'{"disposition":"true_positive","actor":"ceo@evil.com"}',
        user,
        upstream="incident",
    )
    import json

    payload = json.loads(out)
    # incident-api takes the actor from the detection JWT; spoofed body fields are dropped.
    assert "actor" not in payload
    assert "tenant_id" not in payload


def test_inject_actor_stamps_session_email():
    from black_onyx.api.routes_detection import _inject_actor
    from black_onyx.auth.service import Principal, Role

    user = Principal(
        user_id="u3",
        email="alice@onyx.local",
        display_name="Alice",
        role=Role.ANALYST,
    )
    out = _inject_actor(
        "api/v1/incidents/inc-1/disposition",
        "POST",
        b'{"disposition":"true_positive","note":"n"}',
        user,
        upstream="incident",
    )
    import json

    payload = json.loads(out)
    assert payload == {"disposition": "true_positive", "note": "n"}

    training = _inject_actor(
        "api/v1/models/log-model/training-jobs",
        "POST",
        b'{"dataset_id":null,"created_by":"session"}',
        user,
        upstream="training",
    )
    assert json.loads(training)["created_by"] == "alice@onyx.local"


def test_inject_actor_stamps_response_request():
    from black_onyx.api.routes_detection import _inject_actor
    from black_onyx.auth.service import Principal, Role

    user = Principal(
        user_id="u4",
        email="analyst@onyx.local",
        display_name="Analyst",
        role=Role.ANALYST,
    )
    out = _inject_actor(
        "api/v1/response/request",
        "POST",
        b'{"incident_id":"inc-1","playbook_id":"pb","actor":"spoofed"}',
        user,
        upstream="response",
    )
    import json

    assert json.loads(out)["actor"] == "analyst@onyx.local"


def test_inject_actor_rejects_conflicting_body_tenant(monkeypatch):
    from fastapi import HTTPException
    from black_onyx.api.routes_detection import _inject_actor
    from black_onyx.auth.service import Principal, Role

    monkeypatch.setenv("BLACK_ONYX_DETECTION_TENANT", "trusted")
    user = Principal(
        user_id="u4", email="analyst@onyx.local",
        display_name="Analyst", role=Role.ANALYST,
    )
    with pytest.raises(HTTPException) as exc:
        _inject_actor(
            "api/v1/response/req-1/approve", "POST",
            b'{"tenant_id":"other","dry_run":true}', user, upstream="response",
        )
    assert exc.value.status_code == 403


def test_inject_actor_uses_header_tenant_for_strict_approval(monkeypatch):
    import json
    from black_onyx.api.routes_detection import _inject_actor
    from black_onyx.auth.service import Principal, Role

    monkeypatch.setenv("BLACK_ONYX_DETECTION_TENANT", "trusted")
    user = Principal(
        user_id="u4", email="analyst@onyx.local",
        display_name="Analyst", role=Role.ANALYST,
    )
    body = _inject_actor(
        "api/v1/response/req-1/approve", "POST",
        b'{"tenant_id":"trusted","dry_run":true,"actor":"spoofed"}', user, upstream="response",
    )
    assert json.loads(body) == {"dry_run": True, "actor": "analyst@onyx.local"}


@pytest.mark.asyncio
async def test_detection_proxy_stops_streaming_oversized_upstream(monkeypatch):
    from starlette.requests import Request

    from black_onyx.api import routes_detection
    from black_onyx.auth.service import Principal, Role

    class FakeUpstream:
        status_code = 200
        headers = {"content-type": "application/json"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def aiter_bytes(self):
            yield b"123"
            yield b"45"

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def stream(self, *_args, **_kwargs):
            return FakeUpstream()

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "client": ("test", 1),
            "server": ("test", 80),
        },
        receive,
    )
    user = Principal(
        user_id="u5",
        email="analyst@onyx.local",
        display_name="Analyst",
        role=Role.ANALYST,
    )
    monkeypatch.setattr(routes_detection, "MAX_PROXY_RESPONSE_BYTES", 4)
    monkeypatch.setattr(routes_detection.httpx, "AsyncClient", lambda **_kwargs: FakeClient())

    response = await routes_detection._proxy(
        request,
        upstream="incident",
        path="api/v1/incidents",
        user=user,
    )

    assert response.status_code == 502
    assert b"too large" in response.body


@pytest.mark.asyncio
async def test_response_reconciliation_proxy_requires_admin_and_server_key(monkeypatch):
    from fastapi import HTTPException
    from starlette.requests import Request

    from black_onyx.api import routes_detection
    from black_onyx.auth.service import Principal, Role

    monkeypatch.setenv("BLACK_ONYX_DETECTION_TENANT", "tenant-a")
    monkeypatch.setenv("RESPONSE_ORCHESTRATOR_APPROVER_API_KEY", "server-held-approver")
    monkeypatch.setenv("RESPONSE_ORCHESTRATOR_API_KEY", "response-service-key")
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    request = Request({
        "type": "http", "http_version": "1.1", "method": "GET", "scheme": "http",
        "path": "/", "raw_path": b"/", "query_string": b"", "headers": [],
        "client": ("test", 1), "server": ("test", 80),
    }, receive)
    def principal(role):
        return Principal(user_id="u1", email="user@example.test", display_name="User", role=role)
    with pytest.raises(HTTPException) as denied:
        await routes_detection._proxy(
            request, upstream="response",
            path="api/v1/response/reconciliation", user=principal(Role.ANALYST),
            service_key_env="RESPONSE_ORCHESTRATOR_API_KEY",
        )
    assert denied.value.status_code == 403

    seen = {}
    class FakeUpstream:
        status_code = 200
        headers = {"content-type": "application/json"}
        async def __aenter__(self): return self
        async def __aexit__(self, *_args): return False
        async def aiter_bytes(self): yield b'{"items":[]}'
    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *_args): return False
        def stream(self, *_args, **kwargs):
            seen.update(kwargs["headers"])
            return FakeUpstream()
    monkeypatch.setattr(routes_detection.httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    response = await routes_detection._proxy(
        request, upstream="response",
        path="api/v1/response/reconciliation", user=principal(Role.ADMIN),
        service_key_env="RESPONSE_ORCHESTRATOR_API_KEY",
    )
    assert response.status_code == 200
    assert seen["X-Approver-Key"] == "server-held-approver"
    scan_request = Request({**request.scope, "method": "POST"}, receive)
    scan = await routes_detection._proxy(
        scan_request, upstream="response",
        path="api/v1/response/reconciliation/scan", user=principal(Role.ADMIN),
        service_key_env="RESPONSE_ORCHESTRATOR_API_KEY",
    )
    assert scan.status_code == 200
    assert seen["X-Approver-Key"] == "server-held-approver"


@pytest.mark.asyncio
async def test_response_request_asset_must_belong_to_incident(monkeypatch):
    import json

    from fastapi import HTTPException

    from black_onyx.api import routes_detection
    from black_onyx.auth.service import Principal, Role

    monkeypatch.setenv("BLACK_ONYX_DETECTION_TENANT", "tenant-a")
    user = Principal(user_id="u1", email="analyst@example.test", display_name="Analyst", role=Role.ANALYST)
    lookups: list[str] = []

    class FakeResponse:
        def __init__(self, status_code, body):
            self.status_code = status_code
            self._body = body

        def json(self):
            return self._body

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *_args): return False

        async def get(self, url, headers):
            lookups.append(url)
            assert headers["X-Tenant-Id"] == "tenant-a"
            if url.endswith("/inc-missing"):
                return FakeResponse(404, {"detail": "not found"})
            return FakeResponse(200, {"incident_id": "inc-1", "assets": ["sensor-edge-01", "wazuh:007"]})

    monkeypatch.setattr(routes_detection.httpx, "AsyncClient", lambda **_kwargs: FakeClient())

    def body(incident_id, asset_id):
        return json.dumps({
            "incident_id": incident_id, "playbook_id": "isolate-host", "payload": {"asset_id": asset_id},
        }).encode()

    await routes_detection._check_response_asset(body("inc-1", "wazuh:007"), user)
    assert lookups[-1].endswith("/api/v1/incidents/inc-1")

    with pytest.raises(HTTPException) as foreign:
        await routes_detection._check_response_asset(body("inc-1", "wazuh:999"), user)
    assert foreign.value.status_code == 422

    with pytest.raises(HTTPException) as missing:
        await routes_detection._check_response_asset(body("inc-missing", "wazuh:007"), user)
    assert missing.value.status_code == 404

    with pytest.raises(HTTPException) as no_incident:
        await routes_detection._check_response_asset(body("", "wazuh:007"), user)
    assert no_incident.value.status_code == 422

    before = len(lookups)
    await routes_detection._check_response_asset(
        json.dumps({"incident_id": "inc-1", "playbook_id": "block-c2", "payload": {}}).encode(), user,
    )
    assert len(lookups) == before
