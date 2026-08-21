from __future__ import annotations

import httpx
import pytest
import respx
from notification_service.db import Base, get_db
from notification_service.formatters import format_slack_payload
from notification_service.main import app
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def _override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_slack_formatter_shape() -> None:
    payload = format_slack_payload(
        {
            "incident_id": "inc-1",
            "tenant_id": "tenant-acme",
            "severity": "critical",
            "title": "Auth anomaly",
            "summary": "multi-model correlation",
        }
    )
    assert "blocks" in payload
    assert payload["text"].startswith("[CRITICAL]")


@respx.mock
def test_webhook_retries_then_succeeds(client: TestClient) -> None:
    route = respx.post("https://hooks.example.com/slack").mock(
        side_effect=[
            httpx.Response(500),
            httpx.Response(500),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    response = client.post(
        "/api/v1/notifications/test",
        json={
            "channels": ["webhook"],
            "webhook_url": "https://hooks.example.com/slack",
            "incident_id": "inc-retry",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["results"]["webhook"]["delivered"] is True
    assert body["results"]["webhook"]["attempts"] == 3
    assert route.call_count == 3


def test_email_outbox(client: TestClient) -> None:
    response = client.post(
        "/api/v1/notifications/test",
        json={"channels": ["email"], "email_to": "oncall@example.com"},
    )
    assert response.status_code == 200
    assert response.json()["results"]["email"]["queued"] is True
    outbox = client.get("/api/v1/notifications/outbox")
    assert outbox.status_code == 200
    items = outbox.json()["items"]
    assert items
    assert items[0]["recipient"] == "oncall@example.com"
