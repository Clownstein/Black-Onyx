from __future__ import annotations

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


def test_list_packs() -> None:
    client = _client()
    r = client.get("/api/v1/security-packs", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) >= 10
    assert any(p["pack_id"] == "cis-v8-ig1" for p in body["items"])
    assert "presets" in body


def test_create_evaluate_export_profile() -> None:
    client = _client()
    create = client.post(
        "/api/v1/security-profiles",
        headers=HEADERS,
        json={
            "name": "Lab CIS",
            "selected_packs": ["cis-v8-ig1", "mitre-attack-core"],
            "enabled_surfaces": ["network", "host", "identity"],
        },
    )
    assert create.status_code == 200, create.text
    profile = create.json()
    pid = profile["profile_id"]
    assert profile["preview"]["auto_count"] >= 1

    ev = client.post(f"/api/v1/security-profiles/{pid}/evaluate", headers=HEADERS)
    assert ev.status_code == 200
    body = ev.json()
    summary = body["summary"]
    assert "pass" in summary and "unknown" in summary
    # Never silent-pass auto checks without telemetry evidence.
    auto_rows = [c for c in body["coverage"] if c["automation"] == "auto"]
    assert auto_rows
    assert all(c["status"] in {"unknown", "fail", "not_applicable"} for c in auto_rows)
    assert all(
        c["reason"] in {"telemetry_missing", "open_finding", "exception"} or c["status"] != "pass"
        for c in auto_rows
    )

    cov = client.get(f"/api/v1/security-profiles/{pid}/coverage", headers=HEADERS)
    assert cov.status_code == 200

    exp = client.get(f"/api/v1/security-profiles/{pid}/export", headers=HEADERS)
    assert exp.status_code == 200
    assert exp.json()["selected_packs"] == ["cis-v8-ig1", "mitre-attack-core"]

    cert = client.post(
        f"/api/v1/security-profiles/{pid}/certification-package",
        headers=HEADERS,
        json={"target": "soc2"},
    )
    assert cert.status_code == 200
    assert "disclaimer" in cert.json()

    cert_csv = client.post(
        f"/api/v1/security-profiles/{pid}/certification-package?export_format=csv",
        headers=HEADERS,
        json={"target": "soc2"},
    )
    assert cert_csv.status_code == 200
    assert "control_id" in cert_csv.text

    cert_zip = client.post(
        f"/api/v1/security-profiles/{pid}/certification-package?export_format=zip",
        headers=HEADERS,
        json={"target": "soc2"},
    )
    assert cert_zip.status_code == 200
    assert cert_zip.headers["content-type"].startswith("application/zip")

    auditor = client.post(
        f"/api/v1/security-profiles/{pid}/certification-package",
        headers={"X-Tenant-Id": "tenant-test", "X-Role": "auditor"},
        json={"target": "soc2"},
    )
    assert auditor.status_code == 200


def test_probe_ok_finding_marks_pass() -> None:
    client = _client()
    create = client.post(
        "/api/v1/security-profiles",
        headers=HEADERS,
        json={
            "name": "TLS",
            "selected_packs": ["surface-webapp"],
            "enabled_surfaces": ["webapp"],
        },
    )
    assert create.status_code == 200
    pid = create.json()["profile_id"]
    # Seed a probe_ok finding for a webapp check if present in pack.
    finding = {
        "finding_id": "f-probe-ok-1",
        "finding_type": "probe_ok",
        "asset_id": "web-1",
        "model_name": "profile-evaluator",
        "model_version": "0.1.0",
        "raw_score": 0.0,
        "calibrated_score": 0.0,
        "window": {"start": "2024-01-01T00:00:00Z", "end": "2024-01-01T00:01:00Z"},
        "compliance": {
            "profile_pack_ids": ["surface-webapp"],
            "check_ids": ["surface.webapp.headers"],
            "surfaces": ["webapp"],
            "automation": "auto",
        },
    }
    posted = client.post("/api/v1/findings", headers=HEADERS, json=finding)
    assert posted.status_code in {200, 201}, posted.text
    ev = client.post(f"/api/v1/security-profiles/{pid}/evaluate", headers=HEADERS)
    assert ev.status_code == 200
    rows = {c["check_id"]: c for c in ev.json()["coverage"]}
    # surface-webapp pack defines this check; probe_ok evidence must flip it to pass.
    assert "surface.webapp.headers" in rows, sorted(rows)
    assert rows["surface.webapp.headers"]["status"] == "pass"
    assert rows["surface.webapp.headers"]["reason"] == "telemetry_ok"
