"""OIDC / RBAC tests for incident-api (parity with asset-registry)."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from incident_api.config import settings
from incident_api.db import Base, get_db
from incident_api.main import app


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


def _incident_payload() -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "title": "RBAC test incident",
        "severity": "high",
        "risk_score": 0.8,
        "status": "open",
        "first_seen": now,
        "last_seen": now,
        "services": ["api"],
        "assets": [],
        "summary": "rbac",
    }


def test_missing_role_defaults_to_viewer_not_admin(client: TestClient) -> None:
    settings.oidc_disabled = True
    try:
        resp = client.post(
            "/api/v1/incidents",
            json=_incident_payload(),
            headers={"X-Tenant-Id": "tenant-a"},
        )
        assert resp.status_code == 403
    finally:
        settings.oidc_disabled = True


def test_viewer_cannot_create_incident(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/incidents",
        json=_incident_payload(),
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "viewer"},
    )
    assert resp.status_code == 403


def test_analyst_can_create_incident(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/incidents",
        json=_incident_payload(),
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "analyst"},
    )
    assert resp.status_code == 201


def test_oidc_hs256_token_allows_analyst(client: TestClient) -> None:
    secret = "incident-test-secret-32bytes-min!!"
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
            "/api/v1/incidents",
            json=_incident_payload(),
            headers={
                "X-Tenant-Id": "tenant-a",
                "Authorization": f"Bearer {token}",
            },
        )
        assert resp.status_code == 201
    finally:
        settings.oidc_hs_secret = ""
        settings.oidc_disabled = True
