from __future__ import annotations

import httpx
import pytest
import respx
from notification_service import config
from notification_service.db import Base, get_db
from notification_service.formatters import format_slack_payload
from notification_service.main import app
from notification_service.models import EmailOutbox, WebhookDelivery
from notification_service.network import request_public_https_sync, validate_public_https_url
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(config.settings, "notification_api_key", "test-notification-key")
    monkeypatch.setattr(config.settings, "notification_webhook_url", "")
    monkeypatch.setattr(config.settings, "notification_webhook_secret", "test-webhook-secret")
    monkeypatch.setattr(
        "notification_service.delivery.validate_public_https_url",
        lambda url: url,
    )
    monkeypatch.setattr("notification_service.main.validate_public_https_url", lambda url: url)

    def mocked_bounded_request(client, method, url, *, max_bytes, headers=None, **kwargs):
        response = client.request(method, url, headers=headers, **kwargs)
        if len(response.content) > max_bytes:
            raise ValueError("test response exceeds configured bound")
        return response

    monkeypatch.setattr(
        "notification_service.delivery.request_public_https_sync",
        mocked_bounded_request,
    )
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
    with TestClient(
        app,
        headers={"X-API-Key": "test-notification-key", "X-Tenant-Id": "tenant-acme"},
    ) as test_client:
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


def test_unconfigured_api_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "notification_api_key", "")
    with TestClient(app) as unconfigured:
        assert unconfigured.get("/health/ready").status_code == 503
        response = unconfigured.post("/api/v1/notifications/test", json={"channels": []})
    assert response.status_code == 503


def test_webhook_url_rejects_private_and_plain_http(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        validate_public_https_url("http://hooks.example.com/path")
    monkeypatch.setattr(
        "notification_service.network.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="non-public"):
        validate_public_https_url("https://hooks.example.com/path")


def test_webhook_request_pins_dns_and_preserves_tls_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "notification_service.network.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    seen = {}

    def respond(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        return httpx.Response(204)

    with httpx.Client(transport=httpx.MockTransport(respond), trust_env=False) as outgoing:
        response = request_public_https_sync(
            outgoing, "POST", "https://hooks.example.com/notify",
            max_bytes=1024, headers={"Content-Type": "application/json"}, content=b"{}",
        )
    request = seen["request"]
    assert response.status_code == 204
    assert request.url.host == "93.184.216.34"
    assert request.headers["host"] == "hooks.example.com"
    assert request.extensions["sni_hostname"] == "hooks.example.com"


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


def test_incident_notification_validates_contract_and_rejects_extra_fields(
    client: TestClient,
) -> None:
    incident = {
        "incident_id": "inc-1",
        "tenant_id": "tenant-acme",
        "title": "Validated incident",
        "status": "open",
        "severity": "high",
        "risk_score": 0.8,
        "category": [],
        "first_seen": "2026-09-03T12:00:00Z",
        "last_seen": "2026-09-03T12:01:00Z",
        "assets": [],
        "services": [],
        "finding_ids": [],
        "summary": "summary",
        "models": [],
        "notify_email": "oncall@example.com",
    }
    accepted = client.post("/api/v1/notifications/incident", json=incident)
    rejected = client.post(
        "/api/v1/notifications/incident",
        json={**incident, "unexpected": "not accepted"},
    )

    assert accepted.status_code == 200, accepted.json()
    assert rejected.status_code == 422


@respx.mock
def test_incident_webhook_outcome_is_durable_and_idempotent(client: TestClient) -> None:
    route = respx.post("https://hooks.example.com/incidents").mock(
        return_value=httpx.Response(204)
    )
    incident = {
        "incident_id": "inc-idempotent",
        "tenant_id": "tenant-acme",
        "title": "Idempotent alert",
        "status": "open",
        "severity": "high",
        "risk_score": 0.8,
        "category": [],
        "first_seen": "2026-09-03T12:00:00Z",
        "last_seen": "2026-09-03T12:01:00Z",
        "assets": [],
        "services": [],
        "finding_ids": [],
        "summary": "stable event",
        "models": [],
        "notification_policy": [{
            "channel": "webhook",
            "enabled": True,
            "config": {
                "webhook_url": "https://hooks.example.com/incidents",
                "webhook_secret": "tenant-webhook-secret",
            },
        }],
    }
    first = client.post("/api/v1/notifications/incident", json=incident)
    second = client.post("/api/v1/notifications/incident", json=incident)
    assert first.status_code == second.status_code == 200
    assert first.json()["webhook"]["delivered"] is True
    assert second.json()["webhook"]["replayed"] is True
    assert route.call_count == 1

    db_factory = app.dependency_overrides[get_db]
    db_iter = db_factory()
    db = next(db_iter)
    try:
        rows = db.query(WebhookDelivery).all()
        assert len(rows) == 1
        assert rows[0].status == "delivered"
        assert rows[0].attempt_count == 1
    finally:
        db_iter.close()


@respx.mock
def test_retryable_webhook_failure_reuses_durable_delivery_id(client: TestClient) -> None:
    route = respx.post("https://hooks.example.com/retry").mock(
        side_effect=[httpx.Response(503) for _ in range(config.settings.webhook_max_retries)]
        + [httpx.Response(204)]
    )
    incident = {
        "incident_id": "inc-retryable",
        "tenant_id": "tenant-acme",
        "title": "Retry alert",
        "status": "open",
        "severity": "high",
        "risk_score": 0.8,
        "category": [],
        "first_seen": "2026-09-03T12:00:00Z",
        "last_seen": "2026-09-03T12:01:00Z",
        "assets": [],
        "services": [],
        "finding_ids": [],
        "summary": "retryable event",
        "models": [],
        "notification_policy": [{
            "channel": "webhook", "enabled": True,
            "config": {
                "webhook_url": "https://hooks.example.com/retry",
                "webhook_secret": "tenant-webhook-secret",
            },
        }],
    }
    first = client.post("/api/v1/notifications/incident", json=incident).json()["webhook"]
    second = client.post("/api/v1/notifications/incident", json=incident).json()["webhook"]
    assert first["delivered"] is False and first["retryable"] is True
    assert second["delivered"] is True
    assert route.call_count == config.settings.webhook_max_retries + 1
    first_delivery_id = route.calls[0].request.headers["X-Black-Onyx-Delivery-Id"]
    assert all(
        call.request.headers["X-Black-Onyx-Delivery-Id"] == first_delivery_id
        for call in route.calls
    )


def test_all_enabled_channel_destinations_validate_before_email_queue(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def invalid_destination(_url: str) -> str:
        raise ValueError("private address")

    monkeypatch.setattr("notification_service.main.validate_public_https_url", invalid_destination)
    response = client.post("/api/v1/notifications/incident", json={
        "incident_id": "inc-invalid-webhook",
        "tenant_id": "tenant-acme",
        "title": "No partial side effects",
        "status": "open",
        "severity": "high",
        "risk_score": 0.8,
        "category": [],
        "first_seen": "2026-09-03T12:00:00Z",
        "last_seen": "2026-09-03T12:01:00Z",
        "assets": [],
        "services": [],
        "finding_ids": [],
        "summary": "invalid destination",
        "models": [],
        "notify_email": "oncall@example.com",
        "notification_policy": [
            {"channel": "email", "enabled": True, "config": {"email_to": "oncall@example.com"}},
            {"channel": "webhook", "enabled": True, "config": {
                "webhook_url": "https://hooks.example.com/private",
                "webhook_secret": "tenant-webhook-secret",
            }},
        ],
    })
    assert response.status_code == 422
    assert client.get("/api/v1/notifications/outbox").json()["items"] == []


def test_notification_body_limit_is_enforced_before_validation(client: TestClient) -> None:
    response = client.post(
        "/api/v1/notifications/test",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": str(2 * 1024 * 1024)},
    )
    assert response.status_code == 413


def test_email_requires_explicit_or_configured_recipient(client: TestClient) -> None:
    response = client.post(
        "/api/v1/notifications/test",
        json={"channels": ["email"], "email_to": None},
    )
    assert response.status_code == 422


def test_flush_without_smtp_fails_retryably(client: TestClient) -> None:
    queued = client.post(
        "/api/v1/notifications/test",
        json={"channels": ["email"], "email_to": "oncall@example.com"},
    )
    assert queued.status_code == 200
    flushed = client.post("/api/v1/notifications/outbox/flush")
    assert flushed.status_code == 200
    assert flushed.json()["failed"] == 1
    row = client.get("/api/v1/notifications/outbox").json()["items"][0]
    assert row["status"] == "failed"
    assert row["delivery_mode"] == "smtp"
    assert row["retryable"] is True


def test_failed_email_is_retried_by_outbox_flush(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config.settings, "outbox_retry_seconds", 0)
    client.post("/api/v1/notifications/test", json={
        "channels": ["email"], "email_to": "oncall@example.com",
    })
    assert client.post("/api/v1/notifications/outbox/flush").json()["failed"] == 1
    monkeypatch.setattr("notification_service.delivery._send_smtp", lambda *_: {
        "delivered": True, "mode": "smtp",
    })
    retried = client.post("/api/v1/notifications/outbox/flush")
    assert retried.json()["sent"] == 1
    row = client.get("/api/v1/notifications/outbox").json()["items"][0]
    assert row["status"] == "sent"
    assert row["attempt_count"] == 2


def test_smtp_delivery_is_recorded_as_sent(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeSmtp:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def starttls(self):
            return None

        def send_message(self, _message):
            return None

    monkeypatch.setattr(config.settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(config.settings, "smtp_from", "alerts@example.test")
    monkeypatch.setattr("smtplib.SMTP", FakeSmtp)
    client.post(
        "/api/v1/notifications/test",
        json={"channels": ["email"], "email_to": "oncall@example.com"},
    )
    flushed = client.post("/api/v1/notifications/outbox/flush")
    assert flushed.json()["sent"] == 1
    row = client.get("/api/v1/notifications/outbox").json()["items"][0]
    assert row["status"] == "sent"
    assert row["delivery_mode"] == "smtp"


@respx.mock
def test_webhook_failure_reports_retry_metadata(client: TestClient) -> None:
    route = respx.post("https://hooks.example.com/fail").mock(return_value=httpx.Response(503))
    response = client.post(
        "/api/v1/notifications/test",
        json={"channels": ["webhook"], "webhook_url": "https://hooks.example.com/fail"},
    )
    body = response.json()["results"]["webhook"]
    assert body["delivered"] is False
    assert body["attempts"] == config.settings.webhook_max_retries
    assert body["error"] == "HTTP 503"
    assert route.call_count == config.settings.webhook_max_retries


def test_failed_outbox_can_be_retried(client: TestClient) -> None:
    queued = client.post(
        "/api/v1/notifications/test",
        json={"channels": ["email"], "email_to": "oncall@example.com"},
    ).json()
    outbox_id = queued["results"]["email"]["outbox_id"]
    db_factory = app.dependency_overrides[get_db]
    db_iter = db_factory()
    db = next(db_iter)
    try:
        row = db.get(EmailOutbox, outbox_id)
        assert row is not None
        row.status = "failed"
        row.last_error = "smtp unavailable"
        db.commit()
    finally:
        db_iter.close()
    retried = client.post(f"/api/v1/notifications/outbox/{outbox_id}/retry")
    assert retried.status_code == 200
    assert retried.json()["status"] == "pending"


def test_outbox_operations_are_tenant_scoped(client: TestClient) -> None:
    queued = client.post(
        "/api/v1/notifications/test",
        json={"channels": ["email"], "email_to": "oncall@example.com"},
    ).json()
    outbox_id = queued["results"]["email"]["outbox_id"]

    other_list = client.get(
        "/api/v1/notifications/outbox", headers={"X-Tenant-Id": "tenant-b"}
    )
    other_retry = client.post(
        f"/api/v1/notifications/outbox/{outbox_id}/retry",
        headers={"X-Tenant-Id": "tenant-b"},
    )

    assert other_list.status_code == 200
    assert other_list.json()["items"] == []
    assert other_retry.status_code == 404
