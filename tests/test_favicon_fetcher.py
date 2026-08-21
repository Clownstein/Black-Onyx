"""SSRF-focused tests for the favicon fetcher.

The favicon fetch is server-initiated and runs on behalf of any
authenticated user (including viewers), so it must never be usable to probe
private networks or cloud metadata endpoints. Every case below resolves to
an address the fetcher must refuse *before* it ever calls httpx — no network
access is required to run these tests, and none should occur.
"""

from __future__ import annotations

from black_onyx.favicon_fetcher import _resolves_to_public_address, fetch_and_cache_favicon


def test_resolves_to_public_address_rejects_loopback():
    assert _resolves_to_public_address("127.0.0.1") is False
    assert _resolves_to_public_address("localhost") is False
    assert _resolves_to_public_address("::1") is False


def test_resolves_to_public_address_rejects_private_ranges():
    assert _resolves_to_public_address("10.0.0.5") is False
    assert _resolves_to_public_address("172.16.4.4") is False
    assert _resolves_to_public_address("192.168.1.1") is False


def test_resolves_to_public_address_rejects_cloud_metadata():
    assert _resolves_to_public_address("169.254.169.254") is False


def test_resolves_to_public_address_rejects_unresolvable_host():
    assert _resolves_to_public_address("this-host-does-not-exist.invalid") is False


def test_resolves_to_public_address_accepts_a_literal_public_ip():
    # A well-known public anycast address — literal IP, no DNS needed.
    assert _resolves_to_public_address("1.1.1.1") is True


def test_fetch_and_cache_favicon_refuses_private_and_metadata_urls(tmp_path):
    state_dir = str(tmp_path)
    assert fetch_and_cache_favicon("https://127.0.0.1/", state_dir, "s1") is None
    assert fetch_and_cache_favicon("https://10.0.0.5/", state_dir, "s2") is None
    assert fetch_and_cache_favicon("https://169.254.169.254/", state_dir, "s3") is None
    assert fetch_and_cache_favicon("https://[::1]/", state_dir, "s4") is None
    # No fetch should have gotten far enough to write anything to disk.
    favicons_dir = tmp_path / "favicons"
    assert not favicons_dir.exists() or not any(favicons_dir.iterdir())


def test_fetch_and_cache_favicon_rejects_non_http_scheme(tmp_path):
    assert fetch_and_cache_favicon("ftp://example.com/", str(tmp_path), "s5") is None
    assert fetch_and_cache_favicon("javascript:alert(1)", str(tmp_path), "s6") is None
