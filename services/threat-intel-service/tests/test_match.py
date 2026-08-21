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
            app, headers={"X-Service-Key": "dev-threat-intel-key"}
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
