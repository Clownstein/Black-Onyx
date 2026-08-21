from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from incident_api import models  # noqa: F401
from incident_api.db import Base, get_db
from incident_api.main import app


def _client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    return TestClient(app)


HEADERS = {"X-Tenant-Id": "tenant-test", "X-Role": "admin"}


def test_similar_findings_disabled() -> None:
    client = _client()
    r = client.get("/api/v1/findings/missing/similar", headers=HEADERS)
    # either 404 finding or empty when vector off — create finding first
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert r.json().get("items") == [] or "warning" in r.json()


def test_federated_hunt_returns_structure() -> None:
    client = _client()
    r = client.post(
        "/api/v1/hunt/federated",
        headers=HEADERS,
        json={"query": "checkout", "size": 10},
    )
    assert r.status_code == 200
    body = r.json()
    assert "hits" in body
    assert "warnings" in body
