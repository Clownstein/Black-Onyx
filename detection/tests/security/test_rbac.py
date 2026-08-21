"""RBAC and OIDC-disabled role enforcement for mutating incident APIs."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "services" / "incident-api"))

from incident_api.config import settings
from incident_api.db import Base, get_db
from incident_api.main import app

# Header-role tests require OIDC-off (production default is fail-closed).
settings.oidc_disabled = True


def _client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Session = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    return TestClient(app)


def test_viewer_cannot_create_incident():
    client = _client()
    now = datetime.now(UTC).isoformat()
    denied = client.post(
        "/api/v1/incidents",
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "viewer"},
        json={
            "title": "blocked",
            "severity": "low",
            "risk_score": 0.1,
            "first_seen": now,
            "last_seen": now,
            "assets": ["a"],
            "services": [],
            "finding_ids": [],
        },
    )
    assert denied.status_code == 403


def test_analyst_can_create_and_service_key_bypasses_role():
    client = _client()
    now = datetime.now(UTC).isoformat()
    ok = client.post(
        "/api/v1/incidents",
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "analyst"},
        json={
            "title": "ok",
            "severity": "medium",
            "risk_score": 0.5,
            "first_seen": now,
            "last_seen": now,
            "assets": ["a"],
            "services": [],
            "finding_ids": [],
        },
    )
    assert ok.status_code == 201

    from incident_api.config import settings

    settings.service_api_key = "svc-test-key"
    try:
        svc = client.post(
            "/api/v1/incidents",
            headers={
                "X-Tenant-Id": "tenant-a",
                "X-Service-Key": "svc-test-key",
                "X-Role": "viewer",
            },
            json={
                "title": "service",
                "severity": "high",
                "risk_score": 0.8,
                "first_seen": now,
                "last_seen": now,
                "assets": ["b"],
                "services": [],
                "finding_ids": [],
            },
        )
        assert svc.status_code == 201
    finally:
        settings.service_api_key = ""


def test_invalid_hs256_bearer_returns_401_not_500():
    """An malformed/invalid HS256 bearer token must yield 401, not a 500 leak."""
    client = _client()
    from incident_api.config import settings

    settings.oidc_disabled = False
    settings.oidc_hs_secret = "test-secret"
    settings.oidc_issuer = ""
    settings.oidc_audience = ""
    try:
        resp = client.post(
            "/api/v1/incidents",
            headers={
                "X-Tenant-Id": "tenant-a",
                "Authorization": "Bearer not-a-valid-jwt",
                "X-Role": "analyst",
            },
            json={
                "title": "x",
                "severity": "low",
                "risk_score": 0.1,
                "first_seen": "2026-07-26T00:00:00+00:00",
                "last_seen": "2026-07-26T00:00:00+00:00",
                "assets": ["a"],
                "services": [],
                "finding_ids": [],
            },
        )
        assert resp.status_code == 401
    finally:
        settings.oidc_hs_secret = ""
        settings.oidc_disabled = True
