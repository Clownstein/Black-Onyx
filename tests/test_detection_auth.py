"""Tests for detection-plane JWT minting (Black Onyx → absorbed AA APIs)."""

import os

import pytest

from black_onyx.detection_auth import mint_detection_token


@pytest.fixture(autouse=True)
def _auth_secret(monkeypatch):
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-for-detection-jwt-minting-ok")
    monkeypatch.delenv("BLACK_ONYX_AA_JWT_SECRET", raising=False)
    monkeypatch.delenv("OIDC_HS_SECRET", raising=False)


def test_mint_detection_token_is_three_segments():
    token = mint_detection_token(subject="analyst@example.com", role="analyst")
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

    token = mint_detection_token(subject="viewer@example.com", role="viewer")
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
    )
    import json

    payload = json.loads(out)
    assert payload["actor"] == "alice@onyx.local"


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
    )
    import json

    payload = json.loads(out)
    assert payload["actor"] == "alice@onyx.local"
    assert payload["disposition"] == "true_positive"

    training = _inject_actor(
        "api/v1/models/log-model/training-jobs",
        "POST",
        b'{"dataset_id":null,"created_by":"session"}',
        user,
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
        b'{"incident_id":"inc-1","actor":"spoofed"}',
        user,
    )
    import json

    assert json.loads(out)["actor"] == "analyst@onyx.local"
