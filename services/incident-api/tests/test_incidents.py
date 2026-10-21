from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from incident_api.api import _legacy_evidence_thin, _legacy_incident_summary
from incident_api.db import Base, get_db
from incident_api.main import app
from incident_api.schemas import EvidenceItem


def _client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    return TestClient(app)


def test_create_list_disposition_tenant_isolation():
    client = _client()
    headers_a = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}
    headers_b = {"X-Tenant-Id": "tenant-b", "X-Role": "analyst"}
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "title": "Test incident",
        "severity": "high",
        "risk_score": 0.9,
        "category": ["anomaly"],
        "first_seen": now,
        "last_seen": now,
        "assets": ["host-1"],
        "services": ["payments-api"],
        "finding_ids": ["f1"],
        "summary": "demo",
    }
    created = client.post("/api/v1/incidents", json=payload, headers=headers_a)
    assert created.status_code == 201
    incident_id = created.json()["incident_id"]

    listed_a = client.get("/api/v1/incidents", headers=headers_a)
    assert listed_a.status_code == 200
    assert len(listed_a.json()["items"]) == 1

    listed_b = client.get("/api/v1/incidents", headers=headers_b)
    assert listed_b.status_code == 200
    assert listed_b.json()["items"] == []

    other = client.get(f"/api/v1/incidents/{incident_id}", headers=headers_b)
    assert other.status_code == 404

    disp = client.post(
        f"/api/v1/incidents/{incident_id}/disposition",
        json={"disposition": "false_positive"},
        headers=headers_a,
    )
    assert disp.status_code == 200
    assert disp.json()["disposition"] == "false_positive"


def test_list_incidents_filters_by_site_id():
    client = _client()
    headers = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}
    now = datetime.now(timezone.utc).isoformat()
    base = {
        "severity": "medium",
        "risk_score": 0.5,
        "category": ["anomaly"],
        "first_seen": now,
        "last_seen": now,
        "assets": ["host-1"],
        "services": [],
        "finding_ids": [],
    }
    a = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={**base, "title": "site-a", "context": {"site_id": "plant-a"}},
    )
    b = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={**base, "title": "site-b", "context": {"site_id": "plant-b"}},
    )
    assert a.status_code == 201
    assert b.status_code == 201

    filtered = client.get("/api/v1/incidents", headers=headers, params={"site_id": "plant-a"})
    assert filtered.status_code == 200
    items = filtered.json()["items"]
    assert len(items) == 1
    assert items[0]["title"] == "site-a"
    assert items[0]["context"]["site_id"] == "plant-a"


def test_legacy_summary_and_thin_evidence_helpers():
    assert _legacy_incident_summary(None) is True
    assert _legacy_incident_summary("calibrated_score=0.82") is True
    assert _legacy_incident_summary("findings from 3 models features=max_log_score") is True
    assert _legacy_incident_summary("Privilege change then new peer") is False
    thin = [
        EvidenceItem(
            kind="log",
            model="log-transformer",
            title="calibrated_score=0.91",
            detail="calibrated_score=0.910",
            score=0.91,
            timestamp=datetime.now(timezone.utc),
            raw={},
        )
    ]
    assert _legacy_evidence_thin(thin) is True
    assert _legacy_evidence_thin([]) is True
    rich = [
        EvidenceItem(
            kind="log",
            model="log-transformer",
            title="Unexpected privilege change",
            detail="template tpl-privilege-change fired",
            score=0.91,
            timestamp=datetime.now(timezone.utc),
            raw={"finding_id": "f1"},
        )
    ]
    assert _legacy_evidence_thin(rich) is False


def test_read_rehydrates_thin_evidence_from_findings():
    client = _client()
    headers = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}
    now = datetime.now(timezone.utc).isoformat()
    finding = client.post(
        "/api/v1/findings",
        headers=headers,
        json={
            "finding_id": "f-rehydrate-1",
            "finding_type": "log_anomaly",
            "asset_id": "host-1",
            "calibrated_score": 0.91,
            "model_name": "log-transformer",
            "window": {"start": now, "end": now},
            "title": "Unexpected privilege change",
            "summary": "template tpl-privilege-change fired",
            "contributors": [{"type": "unexpected_template", "template_id": "tpl-privilege-change"}],
            "context": {"summary": "template tpl-privilege-change fired"},
            "evidence_refs": [],
        },
    )
    assert finding.status_code == 201, finding.text
    created = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={
            "title": "Thin evidence incident",
            "severity": "high",
            "risk_score": 0.9,
            "category": ["authentication_change"],
            "first_seen": now,
            "last_seen": now,
            "assets": ["host-1"],
            "services": [],
            "finding_ids": ["f-rehydrate-1"],
            "summary": "calibrated_score=0.910",
            "evidence": [
                {
                    "kind": "log",
                    "model": "log-transformer",
                    "title": "calibrated_score=0.91",
                    "detail": "calibrated_score=0.910",
                    "score": 0.91,
                    "timestamp": now,
                    "raw": {},
                }
            ],
        },
    )
    assert created.status_code == 201, created.text
    incident_id = created.json()["incident_id"]
    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["opening_reason"]
    assert "calibrated_score=" not in (body["summary"] or "")
    assert body["evidence"]
    assert any(
        "privilege" in (item.get("detail") or "").lower()
        or "privilege" in (item.get("title") or "").lower()
        or (item.get("raw") or {}).get("finding_id") == "f-rehydrate-1"
        for item in body["evidence"]
    )


def test_list_incidents_filters_by_asset_alias_case_insensitive():
    client = _client()
    headers = {"X-Tenant-Id": "tenant-a", "X-Role": "analyst"}
    now = datetime.now(timezone.utc).isoformat()
    base = {
        "severity": "medium",
        "risk_score": 0.5,
        "category": ["anomaly"],
        "first_seen": now,
        "last_seen": now,
        "services": [],
        "finding_ids": [],
    }
    client.post("/api/v1/incidents", headers=headers, json={**base, "title": "wz", "assets": ["Wazuh:003"]})
    client.post("/api/v1/incidents", headers=headers, json={**base, "title": "other", "assets": ["host-9"]})
    resp = client.get(
        "/api/v1/incidents",
        headers=headers,
        params=[("asset", "es-07"), ("asset", "wazuh:003")],
    )
    assert resp.status_code == 200
    assert [i["title"] for i in resp.json()["items"]] == ["wz"]
