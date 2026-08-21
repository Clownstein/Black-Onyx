"""OIDC / RBAC parity tests for asset-registry (mirrors incident-api patterns)."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import asynccontextmanager

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from asset_registry.config import settings
from asset_registry.db import Base, get_db
from asset_registry.main import app


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db() -> Generator[Session, None, None]:
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    @asynccontextmanager
    async def test_lifespan(_app):
        yield

    app.dependency_overrides[get_db] = override_get_db
    original_lifespan = app.router.lifespan_context
    app.router.lifespan_context = test_lifespan
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.router.lifespan_context = original_lifespan
        Base.metadata.drop_all(bind=engine)


_ASSET = {
    "asset_id": "host-rbac-01",
    "asset_type": "virtual_machine",
    "name": "rbac-host",
    "service_id": "api",
    "environment": "production",
    "criticality": 0.5,
    "owner_team": "secops",
    "network_zone": "application",
    "expected_peers": [],
    "tags": {},
    "active": True,
}


def test_auditor_role_has_viewer_parity() -> None:
    # Regression: incident_api.tenant added an "auditor" -> "viewer" alias that
    # asset_registry.tenant lacked, so an auditor caller was silently rejected
    # here while accepted there. Keep both ROLE_ALIASES maps in sync.
    from asset_registry.tenant import Principal

    principal = Principal(tenant_id="tenant-a", roles={"auditor"})
    assert principal.has_at_least("viewer") is True
    assert principal.has_at_least("analyst") is False


def test_auditor_can_read_but_not_write_assets(client: TestClient) -> None:
    read_resp = client.get(
        "/api/v1/assets",
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "auditor"},
    )
    assert read_resp.status_code == 200

    write_resp = client.post(
        "/api/v1/assets",
        json={**_ASSET, "asset_id": "host-auditor-01"},
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "auditor"},
    )
    assert write_resp.status_code == 403


def test_viewer_cannot_create_asset(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/assets",
        json=_ASSET,
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "viewer"},
    )
    assert resp.status_code == 403


def test_analyst_can_create_asset(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/assets",
        json=_ASSET,
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "analyst"},
    )
    assert resp.status_code == 201
    assert resp.json()["asset_id"] == "host-rbac-01"


def test_service_key_bypasses_role(client: TestClient) -> None:
    settings.service_api_key = "svc-asset-key"
    try:
        resp = client.post(
            "/api/v1/assets",
            json={**_ASSET, "asset_id": "host-svc-01"},
            headers={
                "X-Tenant-Id": "tenant-a",
                "X-Service-Key": "svc-asset-key",
                "X-Role": "viewer",
            },
        )
        assert resp.status_code == 201
    finally:
        settings.service_api_key = ""


def test_oidc_enabled_invalid_bearer_returns_401(client: TestClient) -> None:
    settings.oidc_disabled = False
    settings.oidc_hs_secret = "asset-test-secret-32bytes-minimum!!"
    settings.oidc_issuer = ""
    settings.oidc_audience = ""
    try:
        resp = client.post(
            "/api/v1/assets",
            json=_ASSET,
            headers={
                "X-Tenant-Id": "tenant-a",
                "Authorization": "Bearer not-a-valid-jwt",
                "X-Role": "analyst",
            },
        )
        assert resp.status_code == 401
    finally:
        settings.oidc_hs_secret = ""
        settings.oidc_disabled = True


def test_oidc_hs256_token_allows_analyst(client: TestClient) -> None:
    secret = "asset-test-secret-32bytes-minimum!!"
    settings.oidc_disabled = False
    settings.oidc_hs_secret = secret
    settings.oidc_issuer = ""
    settings.oidc_audience = ""
    try:
        token = jwt.encode(
            {
                "sub": "user-1",
                "exp": 4102444800,
                "roles": ["analyst"],
                "tenant_id": "tenant-a",
            },
            secret,
            algorithm="HS256",
        )
        resp = client.post(
            "/api/v1/assets",
            json={**_ASSET, "asset_id": "host-oidc-01"},
            headers={
                "X-Tenant-Id": "tenant-a",
                "Authorization": f"Bearer {token}",
            },
        )
        assert resp.status_code == 201
    finally:
        settings.oidc_hs_secret = ""
        settings.oidc_disabled = True
