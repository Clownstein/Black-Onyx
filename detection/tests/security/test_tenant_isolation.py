"""Cross-tenant access must fail for incident reads."""

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

settings.oidc_disabled = True


def test_cross_tenant_denied():
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
    client = TestClient(app)
    now = datetime.now(UTC).isoformat()
    resp = client.post(
        "/api/v1/incidents",
        headers={"X-Tenant-Id": "tenant-a", "X-Role": "analyst"},
        json={
            "title": "secret",
            "severity": "critical",
            "risk_score": 0.99,
            "first_seen": now,
            "last_seen": now,
            "assets": ["a"],
            "services": [],
            "finding_ids": [],
        },
    )
    assert resp.status_code == 201
    iid = resp.json()["incident_id"]
    denied = client.get(f"/api/v1/incidents/{iid}", headers={"X-Tenant-Id": "tenant-b", "X-Role": "analyst"})
    assert denied.status_code == 404
