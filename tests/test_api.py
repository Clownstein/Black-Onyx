"""Security-focused API contract tests."""

import pytest
from fastapi.testclient import TestClient
from urllib.parse import parse_qs, urlsplit


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("QDRANT_STORAGE__STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("QDRANT_SECURITY__EXTERNAL_URL", "http://testserver")
    monkeypatch.setenv("BLACK_ONYX_AUTH_SECRET", "test-secret-that-is-long-and-random")
    monkeypatch.setenv("QDRANT_FEEDS__ENABLED", "false")
    monkeypatch.setenv("QDRANT_CONNECTORS__ENABLED", "false")
    # Host/Compose may inject provider keys; this test asserts write-only secret
    # status starting from unset, so clear deployment secrets for isolation.
    for env_name in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "FIRECRAWL_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "ABUSEIPDB_API_KEY",
        "SHODAN_API_KEY",
        "OTX_API_KEY",
        "MISP_API_KEY",
    ):
        monkeypatch.delenv(env_name, raising=False)
    from black_onyx.config import get_settings
    from black_onyx.auth.context import get_auth_service
    from black_onyx.api.service import AppService
    if AppService._instance is not None:
        AppService._instance._settings_store.database.close()
    AppService._instance = None
    AppService._initialized = False
    get_settings.cache_clear()
    get_auth_service.cache_clear()
    auth = get_auth_service()
    auth.bootstrap_admin("admin@example.com", "correct horse battery staple", "Admin")
    from black_onyx.api.app import create_app
    from unittest.mock import MagicMock
    monkeypatch.setattr(AppService, "ensure_default_collections", lambda self: [])
    monkeypatch.setattr(AppService, "start_background_schedulers", lambda self: None)
    monkeypatch.setattr(AppService, "qdrant_store", property(lambda self: MagicMock()))
    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        yield test_client
    get_auth_service.cache_clear()
    get_settings.cache_clear()
    if AppService._instance is not None:
        AppService._instance._settings_store.database.close()
    AppService._instance = None
    AppService._initialized = False


@pytest.fixture
def authenticated(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        headers={"Origin": "http://testserver"},
        json={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    csrf = response.json()["csrf_token"]
    client.headers.update({"Origin": "http://testserver", "X-CSRF-Token": csrf})
    return client


def test_health_is_public(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_operational_api_requires_authentication(client: TestClient):
    response = client.get("/api/v1/llm/providers")
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")


def test_login_and_current_user(authenticated: TestClient):
    response = authenticated.get("/api/v1/auth/me")
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "admin"


def test_admin_runtime_settings_are_masked_and_persisted(authenticated: TestClient):
    current = authenticated.get("/api/v1/admin/settings")
    assert current.status_code == 200
    payload = current.json()
    assert "qdrant" in payload
    assert payload["secrets"]["openai_api_key"] is False
    payload["llm"]["openai_compatible"]["model"] = "security-model"
    payload["secrets"] = {"openai_api_key": "do-not-return-this-key"}
    updated = authenticated.put("/api/v1/admin/settings", json=payload)
    assert updated.status_code == 200
    body = updated.json()
    assert body["llm"]["openai_compatible"]["model"] == "security-model"
    assert body["secrets"]["openai_api_key"] is True
    assert "do-not-return-this-key" not in updated.text


def test_csrf_is_required(authenticated: TestClient):
    authenticated.headers.pop("X-CSRF-Token")
    response = authenticated.post("/api/v1/sessions", json={"title": "Denied"})
    assert response.status_code == 403


def test_exact_search_validation(authenticated: TestClient):
    response = authenticated.post(
        "/api/v1/search", json={"query": "", "collection": "test"}
    )
    assert response.status_code == 422


def test_session_lifecycle(authenticated: TestClient):
    created = authenticated.post("/api/v1/sessions", json={"title": "Test Session"})
    assert created.status_code == 200
    session_id = created.json()["session_id"]
    listed = authenticated.get("/api/v1/sessions")
    assert listed.status_code == 200
    assert any(item["session_id"] == session_id for item in listed.json())
    deleted = authenticated.delete(f"/api/v1/sessions/{session_id}")
    assert deleted.status_code == 200


def test_legacy_api_is_removed(client: TestClient):
    assert client.get("/api/health").status_code == 401


def test_public_auth_posts_still_require_same_origin(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
    assert response.status_code == 403


def test_invitation_is_single_use_and_role_is_enforced(authenticated: TestClient):
    invitation = authenticated.post(
        "/api/v1/admin/invitations",
        json={"email": "viewer@example.com", "role": "viewer", "send_email": False},
    )
    assert invitation.status_code == 200
    token = parse_qs(urlsplit(invitation.json()["invitation_url"]).query)["token"][0]
    authenticated.cookies.clear()
    registered = authenticated.post(
        "/api/v1/auth/register",
        json={"token": token, "display_name": "Viewer", "password": "another correct horse battery"},
    )
    assert registered.status_code == 200
    authenticated.headers["X-CSRF-Token"] = registered.json()["csrf_token"]
    assert registered.json()["user"]["role"] == "viewer"
    assert authenticated.post("/api/v1/cases", json={"title": "Denied"}).status_code == 403
    second_use = authenticated.post(
        "/api/v1/auth/register",
        json={"token": token, "display_name": "Again", "password": "yet another correct password"},
    )
    assert second_use.status_code == 400


def test_admin_reset_is_single_use_and_invalidates_sessions(authenticated: TestClient):
    user_id = authenticated.get("/api/v1/admin/users").json()["users"][0]["user_id"]
    created = authenticated.post(f"/api/v1/admin/users/{user_id}/password-reset")
    assert created.status_code == 200
    token = parse_qs(urlsplit(created.json()["reset_url"]).query)["token"][0]
    reset = authenticated.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "password": "replacement horse battery staple"},
    )
    assert reset.status_code == 200
    assert authenticated.get("/api/v1/auth/me").status_code == 401
    repeated = authenticated.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "password": "another replacement password"},
    )
    assert repeated.status_code == 400


def _become_viewer(client: TestClient) -> TestClient:
    """Invite and register a viewer, leaving the client on the viewer session."""
    invitation = client.post(
        "/api/v1/admin/invitations",
        json={"email": "viewer@example.com", "role": "viewer", "send_email": False},
    )
    assert invitation.status_code == 200
    token = parse_qs(urlsplit(invitation.json()["invitation_url"]).query)["token"][0]
    client.cookies.clear()
    registered = client.post(
        "/api/v1/auth/register",
        json={"token": token, "display_name": "Viewer", "password": "another correct horse battery"},
    )
    assert registered.status_code == 200
    client.headers["X-CSRF-Token"] = registered.json()["csrf_token"]
    return client


def test_reports_are_shared_records_readable_by_viewers(authenticated: TestClient):
    generated = authenticated.post(
        "/api/v1/reports/generate",
        json={"title": "Shared Report", "format": "markdown", "iocs": {"ips": ["198.51.100.7"]}},
    )
    assert generated.status_code == 200
    report_id = generated.json()["download_url"].split("/")[4]

    listed = authenticated.get("/api/v1/reports").json()["reports"]
    assert [item["report_id"] for item in listed] == [report_id]
    assert listed[0]["created_by"] == "Admin"

    viewer = _become_viewer(authenticated)
    # Generation stays analyst-and-above, but the record itself is shared.
    assert viewer.post("/api/v1/reports/generate", json={"title": "Denied"}).status_code == 403
    assert [item["report_id"] for item in viewer.get("/api/v1/reports").json()["reports"]] == [report_id]
    download = viewer.get(f"/api/v1/reports/{report_id}/download?format=markdown")
    assert download.status_code == 200
    assert "198.51.100.7" in download.text


def test_report_download_requires_a_known_record_and_matching_format(authenticated: TestClient):
    generated = authenticated.post(
        "/api/v1/reports/generate",
        json={"title": "Format Bound", "format": "markdown", "iocs": {}},
    )
    assert generated.status_code == 200
    report_id = generated.json()["download_url"].split("/")[4]
    assert authenticated.get(f"/api/v1/reports/{report_id}/download?format=html").status_code == 404
    unknown = "00000000-0000-4000-8000-000000000000"
    assert authenticated.get(f"/api/v1/reports/{unknown}/download?format=markdown").status_code == 404


def test_reports_listing_requires_authentication(client: TestClient):
    assert client.get("/api/v1/reports").status_code == 401


def test_chat_rejects_browser_supplied_image_paths(authenticated: TestClient):
    response = authenticated.post(
        "/api/v1/chat",
        json={"message": "describe", "images": ["C:/Windows/win.ini"], "use_rag": False},
    )
    assert response.status_code == 422


def test_chat_image_upload_rejects_non_images(authenticated: TestClient):
    response = authenticated.post(
        "/api/v1/chat/images",
        data={"message": "describe", "provider": "local"},
        files={"images": ("evidence.txt", b"not an image", "text/plain")},
    )
    assert response.status_code == 415


def test_viewer_cannot_use_mutating_chat_upload(authenticated: TestClient):
    viewer = _become_viewer(authenticated)
    response = viewer.post(
        "/api/v1/chat/images",
        data={"message": "describe", "provider": "local"},
        files={"images": ("image.png", b"\x89PNG\r\n\x1a\n", "image/png")},
    )
    assert response.status_code == 403


def test_ingestion_ignores_browser_supplied_csv_path(authenticated: TestClient):
    from black_onyx.api.schemas import IngestRequest
    assert "csv_path" not in IngestRequest.model_fields


def test_viewer_may_post_read_only_search_but_not_mutations(authenticated: TestClient):
    viewer = _become_viewer(authenticated)
    assert viewer.post("/api/v1/cases", json={"title": "Denied"}).status_code == 403
    # Search is a read expressed as POST, so the role guard has to allow it.
    assert viewer.post("/api/v1/search", json={"query": "ransomware"}).status_code != 403


# --- Gallery hub: user sites & saved logins ---

def test_decay_summary_is_a_cheap_count_not_a_full_list(authenticated: TestClient):
    response = authenticated.get("/api/v1/decay/summary")
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "tracked_count": 0, "stale_count": 0, "fresh_count": 0, "last_updated": None,
    }


def test_site_crud_lifecycle(authenticated: TestClient):
    created = authenticated.post(
        "/api/v1/sites",
        json={"name": "Internal SIEM", "url": "https://siem.example.com/", "section": "sites", "tags": ["soc"]},
    )
    assert created.status_code == 200
    body = created.json()
    site_id = body["site_id"]
    assert body["name"] == "Internal SIEM"
    assert body["has_credential"] is False
    assert "owner_user_id" not in body

    listed = authenticated.get("/api/v1/sites")
    assert listed.status_code == 200
    assert [s["site_id"] for s in listed.json()] == [site_id]

    updated = authenticated.patch(f"/api/v1/sites/{site_id}", json={"name": "Renamed SIEM", "tags": ["soc", "edr"]})
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed SIEM"
    assert updated.json()["tags"] == ["soc", "edr"]

    deleted = authenticated.delete(f"/api/v1/sites/{site_id}")
    assert deleted.status_code == 200
    assert authenticated.get("/api/v1/sites").json() == []


def test_site_rejects_non_https_and_credential_urls(authenticated: TestClient):
    plain_http = authenticated.post(
        "/api/v1/sites", json={"name": "Insecure", "url": "http://siem.example.com/"},
    )
    assert plain_http.status_code == 422
    with_creds = authenticated.post(
        "/api/v1/sites", json={"name": "Embedded creds", "url": "https://user:pass@siem.example.com/"},
    )
    assert with_creds.status_code == 422
    javascript_url = authenticated.post(
        "/api/v1/sites", json={"name": "XSS", "url": "javascript:alert(1)"},
    )
    assert javascript_url.status_code == 422


def test_viewer_can_manage_their_own_sites(authenticated: TestClient):
    viewer = _become_viewer(authenticated)
    created = viewer.post("/api/v1/sites", json={"name": "Viewer's console", "url": "https://console.example.com/"})
    assert created.status_code == 200
    site_id = created.json()["site_id"]
    assert viewer.delete(f"/api/v1/sites/{site_id}").status_code == 200


def test_site_ownership_is_not_leaked_across_users(authenticated: TestClient):
    created = authenticated.post("/api/v1/sites", json={"name": "Admin's site", "url": "https://admin-only.example.com/"})
    site_id = created.json()["site_id"]
    viewer = _become_viewer(authenticated)
    assert viewer.get(f"/api/v1/sites/{site_id}/favicon").status_code == 404
    assert viewer.patch(f"/api/v1/sites/{site_id}", json={"name": "Hijacked"}).status_code == 404
    assert viewer.delete(f"/api/v1/sites/{site_id}").status_code == 404
    assert viewer.get("/api/v1/sites").json() == []


def test_site_credential_round_trip_and_never_in_list(authenticated: TestClient):
    created = authenticated.post("/api/v1/sites", json={"name": "Vaulted", "url": "https://vaulted.example.com/"})
    site_id = created.json()["site_id"]

    saved = authenticated.post(
        f"/api/v1/sites/{site_id}/credential",
        json={"username": "analyst@example.com", "secret": "hunter2-super-secret", "notes": "shared team login"},
    )
    assert saved.status_code == 200

    listed = authenticated.get("/api/v1/sites").json()
    assert listed[0]["has_credential"] is True
    assert "hunter2-super-secret" not in authenticated.get("/api/v1/sites").text

    revealed = authenticated.get(f"/api/v1/sites/{site_id}/credential")
    assert revealed.status_code == 200
    payload = revealed.json()
    assert payload["username"] == "analyst@example.com"
    assert payload["secret"] == "hunter2-super-secret"
    assert payload["notes"] == "shared team login"

    rotated = authenticated.post(
        f"/api/v1/sites/{site_id}/credential",
        json={"username": "analyst@example.com", "secret": "rotated-secret", "notes": None},
    )
    assert rotated.status_code == 200
    assert authenticated.get(f"/api/v1/sites/{site_id}/credential").json()["secret"] == "rotated-secret"

    removed = authenticated.delete(f"/api/v1/sites/{site_id}/credential")
    assert removed.status_code == 200
    assert authenticated.get("/api/v1/sites").json()[0]["has_credential"] is False
    assert authenticated.get(f"/api/v1/sites/{site_id}/credential").status_code == 404


def test_site_credential_reveal_is_rate_limited_and_audited(authenticated: TestClient):
    created = authenticated.post("/api/v1/sites", json={"name": "Throttled", "url": "https://throttled.example.com/"})
    site_id = created.json()["site_id"]
    authenticated.post(
        f"/api/v1/sites/{site_id}/credential",
        json={"username": "a", "secret": "b"},
    )
    for _ in range(10):
        assert authenticated.get(f"/api/v1/sites/{site_id}/credential").status_code == 200
    limited = authenticated.get(f"/api/v1/sites/{site_id}/credential")
    assert limited.status_code == 429

    from black_onyx.auth.context import get_auth_service
    rows = get_auth_service().db._conn.execute(
        "SELECT action,detail FROM audit_events WHERE action='site_credential.reveal' ORDER BY created_at",
    ).fetchall()
    assert len(rows) == 11
    assert '"outcome":"rate_limited"' in rows[-1]["detail"]
    assert '"outcome":"ok"' in rows[0]["detail"]


def test_site_credential_requires_existing_site(authenticated: TestClient):
    missing_site = "00000000-0000-4000-8000-000000000000"
    response = authenticated.post(
        f"/api/v1/sites/{missing_site}/credential", json={"username": "a", "secret": "b"},
    )
    assert response.status_code == 404


def test_site_update_rejects_explicit_null_for_required_fields(authenticated: TestClient):
    created = authenticated.post("/api/v1/sites", json={"name": "Nullable", "url": "https://nullable.example.com/"})
    site_id = created.json()["site_id"]
    for field in ("name", "url", "section", "open_mode", "tags"):
        response = authenticated.patch(f"/api/v1/sites/{site_id}", json={field: None})
        assert response.status_code == 422, f"{field}=null should be rejected, got {response.status_code}"
    # login_url is the one field that can legitimately be cleared back to null.
    cleared = authenticated.patch(f"/api/v1/sites/{site_id}", json={"login_url": None})
    assert cleared.status_code == 200
    assert cleared.json()["login_url"] is None


def test_site_url_update_invalidates_cached_favicon(authenticated: TestClient):
    from pathlib import Path
    from black_onyx.auth.context import get_auth_service
    from black_onyx.api.service import get_service

    created = authenticated.post("/api/v1/sites", json={"name": "Favicon Site", "url": "https://favicon-site.example.com/"})
    site_id = created.json()["site_id"]
    state_dir = Path(get_service().settings.storage.state_dir)
    relative_path = f"favicons/{site_id}.png"
    favicon_path = state_dir / relative_path
    favicon_path.parent.mkdir(parents=True, exist_ok=True)
    favicon_path.write_bytes(b"fake-cached-favicon-bytes")
    with get_auth_service().db.transaction() as db:
        db.execute("UPDATE user_sites SET favicon_relative_path=? WHERE site_id=?", (relative_path, site_id))

    updated = authenticated.patch(f"/api/v1/sites/{site_id}", json={"url": "https://new-favicon-site.example.com/"})
    assert updated.status_code == 200
    assert not favicon_path.exists(), "stale cached favicon must be removed when the site URL changes"
    row = get_auth_service().db._conn.execute(
        "SELECT favicon_relative_path FROM user_sites WHERE site_id=?", (site_id,),
    ).fetchone()
    assert row["favicon_relative_path"] is None


def test_site_delete_cascades_to_stored_credential(authenticated: TestClient):
    from black_onyx.auth.context import get_auth_service

    created = authenticated.post("/api/v1/sites", json={"name": "Cascade Site", "url": "https://cascade.example.com/"})
    site_id = created.json()["site_id"]
    authenticated.post(f"/api/v1/sites/{site_id}/credential", json={"username": "a", "secret": "b"})
    before = get_auth_service().db._conn.execute(
        "SELECT COUNT(*) AS n FROM stored_credentials WHERE site_id=?", (site_id,),
    ).fetchone()
    assert before["n"] == 1

    deleted = authenticated.delete(f"/api/v1/sites/{site_id}")
    assert deleted.status_code == 200
    after = get_auth_service().db._conn.execute(
        "SELECT COUNT(*) AS n FROM stored_credentials WHERE site_id=?", (site_id,),
    ).fetchone()
    assert after["n"] == 0


def test_connector_crud_lifecycle(authenticated: TestClient):
    """Detection connectors reuse net/safe_url.py's live-DNS SSRF check
    (unlike sites' format-only validate_site_url), so base_url resolution
    must be mocked for every create/update call in this test."""
    from unittest.mock import patch

    with patch(
        "black_onyx.net.safe_url.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    ):
        created = authenticated.post(
            "/api/v1/connectors",
            json={
                "name": "test-falcon", "connector_type": "generic_rest",
                "base_url": "https://api.example.com",
                "config": {"detections_path": "/alerts", "auth": {"type": "api_key_header"}},
                "credential_env": {"api_key": "TEST_API_KEY"},
            },
        )
        assert created.status_code == 200, created.text
        body = created.json()
        connector_id = body["id"]
        assert body["name"] == "test-falcon"
        assert body["collection"] == "detect-test-falcon"
        # credential_env holds only the env var *name*, never a secret value.
        assert body["credential_env"] == {"api_key": "TEST_API_KEY"}

        listed = authenticated.get("/api/v1/connectors")
        assert listed.status_code == 200
        assert [c["id"] for c in listed.json()] == [connector_id]

        patched = authenticated.patch(f"/api/v1/connectors/{connector_id}", json={"enabled": False})
        assert patched.status_code == 200
        assert patched.json()["enabled"] is False

    deleted = authenticated.delete(f"/api/v1/connectors/{connector_id}")
    assert deleted.status_code == 200
    assert authenticated.get("/api/v1/connectors").json() == []


def test_connector_rejects_raw_secret_in_config(authenticated: TestClient):
    from unittest.mock import patch

    with patch(
        "black_onyx.net.safe_url.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    ):
        response = authenticated.post(
            "/api/v1/connectors",
            json={
                "name": "leaky", "connector_type": "generic_rest",
                "base_url": "https://api.example.com",
                "config": {"api_key": "this-should-be-rejected"},
            },
        )
    assert response.status_code == 422


def test_connectors_are_admin_only(authenticated: TestClient):
    """Every /api/v1/connectors* endpoint is org-wide configuration (which
    env vars hold which SIEM/EDR credentials), unlike personal user_sites —
    a viewer must not be able to read or manage it."""
    from unittest.mock import patch

    with patch(
        "black_onyx.net.safe_url.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
    ):
        created = authenticated.post(
            "/api/v1/connectors",
            json={"name": "admin-only-conn", "connector_type": "generic_rest", "base_url": "https://api.example.com"},
        )
    connector_id = created.json()["id"]
    viewer = _become_viewer(authenticated)
    assert viewer.get("/api/v1/connectors").status_code == 403
    assert viewer.post("/api/v1/connectors", json={
        "name": "x", "connector_type": "generic_rest", "base_url": "https://api.example.com",
    }).status_code == 403
    assert viewer.patch(f"/api/v1/connectors/{connector_id}", json={"enabled": False}).status_code == 403
    assert viewer.delete(f"/api/v1/connectors/{connector_id}").status_code == 403
