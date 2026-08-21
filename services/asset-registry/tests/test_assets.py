from collections.abc import Generator
from contextlib import asynccontextmanager

import pytest
from asset_registry.db import Base, get_db
from asset_registry.main import app
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


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


def test_requires_tenant_header(client: TestClient) -> None:
    response = client.get("/api/v1/assets")
    assert response.status_code == 400


def test_tenant_isolation(client: TestClient) -> None:
    payload = {
        "asset_id": "host-payments-03",
        "asset_type": "virtual_machine",
        "name": "payments-api-03",
        "service_id": "payments-api",
        "environment": "production",
        "criticality": 0.9,
        "owner_team": "payments",
        "network_zone": "application",
        "expected_peers": ["payments-db"],
        "tags": {"cloud": "aws"},
        "active": True,
    }
    created = client.post(
        "/api/v1/assets",
        json=payload,
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "analyst"},
    )
    assert created.status_code == 201

    other = client.get("/api/v1/assets", headers={"X-Tenant-Id": "tenant-b"})
    assert other.status_code == 200
    assert other.json() == []

    own = client.get("/api/v1/assets", headers={"X-Tenant-Id": "tenant-a"})
    assert own.status_code == 200
    assert len(own.json()) == 1
    assert own.json()[0]["asset_id"] == "host-payments-03"


def test_zone_tags_round_trip(client: TestClient) -> None:
    headers = {"X-Tenant-Id": "tenant-zones", "X-Role": "analyst"}
    create = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "asset_id": "host-cde-1",
            "asset_type": "host",
            "name": "cde-host",
            "criticality": 0.9,
            "tags": {"zone": "cde", "cui": "true", "ephi": "false", "bes": "false"},
        },
    )
    assert create.status_code == 201
    got = client.get("/api/v1/assets/host-cde-1", headers=headers)
    assert got.status_code == 200
    tags = got.json()["tags"]
    assert tags["zone"] == "cde"
    assert tags["cui"] == "true"


def test_crud_flow(client: TestClient) -> None:
    headers = {"X-Tenant-Id": "tenant-acme", "X-Role": "analyst"}
    create = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "asset_id": "svc-1",
            "asset_type": "service",
            "name": "api",
            "criticality": 0.5,
            "ip_address": "192.0.2.10",
            "notes": "authoritative registry note",
        },
    )
    assert create.status_code == 201

    got = client.get("/api/v1/assets/svc-1", headers=headers)
    assert got.status_code == 200
    assert got.json()["name"] == "api"
    assert got.json()["ip_address"] == "192.0.2.10"
    assert got.json()["notes"] == "authoritative registry note"

    patched = client.patch(
        "/api/v1/assets/svc-1",
        headers=headers,
        json={"name": "api-v2", "active": False},
    )
    assert patched.status_code == 200
    assert patched.json()["name"] == "api-v2"
    assert patched.json()["active"] is False

    deleted = client.delete("/api/v1/assets/svc-1", headers=headers)
    assert deleted.status_code == 204
    missing = client.get("/api/v1/assets/svc-1", headers=headers)
    assert missing.status_code == 404


def test_topology_and_baseline(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "asset_registry.api._load_retained_scores",
        lambda tenant_id, asset_id, start: [0.1, 0.4, 0.9],
    )
    headers = {"X-Tenant-Id": "tenant-acme", "X-Role": "analyst"}
    created = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "asset_id": "host-payments-03",
            "asset_type": "virtual_machine",
            "name": "payments-api-03",
            "expected_peers": ["payments-db", "identity-api"],
        },
    )
    assert created.status_code == 201

    topology = client.get("/api/v1/assets/host-payments-03/topology", headers=headers)
    assert topology.status_code == 200
    body = topology.json()
    assert body["asset_id"] == "host-payments-03"
    assert len(body["nodes"]) == 3
    assert len(body["edges"]) == 2
    assert {e["target"] for e in body["edges"]} == {"payments-db", "identity-api"}

    baseline = client.get("/api/v1/assets/host-payments-03/baseline", headers=headers)
    assert baseline.status_code == 200
    stats = baseline.json()["stats"]
    assert stats["status"] == "ready"
    assert stats["sample_count"] == 3
    assert stats["mean_score"] == pytest.approx(0.4666666667)
    assert stats["p95_score"] == 0.9


def test_viewer_cannot_create_asset(client: TestClient) -> None:
    denied = client.post(
        "/api/v1/assets",
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "viewer"},
        json={
            "asset_id": "blocked",
            "asset_type": "service",
            "name": "blocked",
        },
    )
    assert denied.status_code == 403


def test_service_key_allows_mutate(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from asset_registry.config import settings

    monkeypatch.setattr(settings, "service_api_key", "asset-svc-key")
    created = client.post(
        "/api/v1/assets",
        headers={
            "X-Tenant-Id": "tenant-a",
            "X-Role": "viewer",
            "X-Service-Key": "asset-svc-key",
        },
        json={
            "asset_id": "svc-via-key",
            "asset_type": "service",
            "name": "via-key",
        },
    )
    assert created.status_code == 201


def test_put_upserts_asset_idempotently(client: TestClient) -> None:
    """Collectors re-enroll on every boot, so PUT must never fail on re-run."""
    body = {"asset_type": "host", "name": "onyx-host", "environment": "prod"}
    headers = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}

    created = client.put("/api/v1/assets/self-host", headers=headers, json=body)
    assert created.status_code == 201
    assert created.json()["asset_id"] == "self-host"
    assert created.json()["environment"] == "prod"

    # Same call again: updates in place instead of 409ing like POST does.
    again = client.put("/api/v1/assets/self-host", headers=headers, json=body)
    assert again.status_code == 200

    updated = client.put(
        "/api/v1/assets/self-host",
        headers=headers,
        json={**body, "environment": "lab", "criticality": 0.9},
    )
    assert updated.status_code == 200
    assert updated.json()["environment"] == "lab"
    assert updated.json()["criticality"] == 0.9

    listed = client.get("/api/v1/assets", headers={"X-Tenant-Id": "tenant-a"})
    assert [a["asset_id"] for a in listed.json()].count("self-host") == 1


def test_put_upsert_requires_analyst(client: TestClient) -> None:
    denied = client.put(
        "/api/v1/assets/nope",
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "viewer"},
        json={"asset_type": "host", "name": "nope"},
    )
    assert denied.status_code == 403


def test_put_upsert_is_tenant_scoped(client: TestClient) -> None:
    body = {"asset_type": "host", "name": "shared-id"}
    client.put(
        "/api/v1/assets/dup", headers={"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}, json=body
    )
    other = client.put(
        "/api/v1/assets/dup", headers={"X-Tenant-Id": "tenant-b", "X-Role": "analyst"}, json=body
    )
    # Same asset_id in a different tenant is a distinct row, so this creates.
    assert other.status_code == 201
