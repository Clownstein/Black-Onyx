from collections.abc import Generator
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from threat_intel_service.db import Base, get_db
from threat_intel_service.main import app
from threat_intel_service.store import upsert_indicator


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    from threat_intel_service.config import settings

    monkeypatch.setattr(settings, "service_api_key", "test-threat-key")
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

    # Seed via a one-shot session
    seed = TestingSession()
    upsert_indicator(
        seed,
        {
            "indicator_id": "ind-otx-1.2.3.4",
            "observable_type": "ipv4",
            "observable_value": "203.0.113.50",
            "source": "taxii-demo",
            "confidence": 90,
            "tlp": "amber",
            "campaigns": ["demo-campaign"],
            "mitre_techniques": ["T1071.001"],
        },
    )
    seed.commit()
    seed.close()

    @asynccontextmanager
    async def test_lifespan(_app):
        yield

    app.dependency_overrides[get_db] = override_get_db
    original_lifespan = app.router.lifespan_context
    app.router.lifespan_context = test_lifespan
    try:
        with TestClient(
            app,
            headers={"X-Service-Key": "test-threat-key", "X-Tenant-Id": "tenant-a"},
        ) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.router.lifespan_context = original_lifespan
        Base.metadata.drop_all(bind=engine)


def test_match_endpoint(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/match",
        json={"observables": [{"type": "ipv4", "value": "203.0.113.50"}]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["matches"]) == 1
    assert body["matches"][0]["id"] == "ind-otx-1.2.3.4"
    assert body["matches"][0]["confidence"] == 90
    assert body["campaigns"] == ["demo-campaign"]
    assert body["tlp"] == "amber"


def test_match_miss(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/match",
        json={"observables": [{"type": "ipv4", "value": "198.51.100.1"}]},
    )
    assert resp.status_code == 200
    assert resp.json()["matches"] == []


def test_airgap_blocks_taxii(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    from threat_intel_service.config import settings

    monkeypatch.setattr(settings, "airgap_mode", True)
    resp = client.post("/api/v1/feeds/taxii/sync")
    assert resp.status_code == 403


def test_airgap_blocks_kev(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    from threat_intel_service.config import settings

    monkeypatch.setattr(settings, "airgap_mode", True)
    resp = client.post("/api/v1/feeds/kev/sync")
    assert resp.status_code == 403


def test_match_requires_auth(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/match",
        json={"observables": [{"type": "ipv4", "value": "203.0.113.50"}]},
        headers={"X-Service-Key": "wrong-key"},
    )
    assert resp.status_code == 401


def test_match_fails_closed_when_key_unconfigured(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    from threat_intel_service.config import settings

    monkeypatch.setattr(settings, "service_api_key", "")
    response = client.post("/api/v1/match", json={"observables": []})
    assert response.status_code == 503


def test_indicator_upsert_rejects_empty_batch(client: TestClient) -> None:
    response = client.post("/api/v1/indicators/upsert", json={"indicators": []})
    assert response.status_code == 422


def test_request_body_limit_rejects_before_json_parsing(client: TestClient) -> None:
    response = client.post(
        "/api/v1/indicators/upload-stix",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": str(17 * 1024 * 1024)},
    )
    assert response.status_code == 413


def test_exact_match_does_not_leak_other_tenant_indicator(client: TestClient) -> None:
    override = app.dependency_overrides[get_db]
    iterator = override()
    db = next(iterator)
    try:
        upsert_indicator(
            db,
            {
                "indicator_id": "tenant-b-only",
                "tenant_id": "tenant-b",
                "observable_type": "domain",
                "observable_value": "private-b.example",
                "source": "tenant-feed",
            },
        )
        db.commit()
    finally:
        iterator.close()

    tenant_a = client.post(
        "/api/v1/match",
        json={"observables": [{"type": "domain", "value": "private-b.example"}]},
    )
    tenant_b = client.post(
        "/api/v1/match",
        headers={"X-Tenant-Id": "tenant-b"},
        json={"observables": [{"type": "domain", "value": "private-b.example"}]},
    )
    assert tenant_a.json()["matches"] == []
    assert len(tenant_b.json()["matches"]) == 1
