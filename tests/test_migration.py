"""Tests for the payload migration script (migrate_payloads.py)."""

import sys
from pathlib import Path


# Add scripts dir to path for import
scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from migrate_payloads import migrate_payload, FIELD_RENAMES  # noqa: E402


class TestMigratePayload:
    def test_rename_singular_to_plural(self):
        payload = {"domain": "evil.com", "ip": "1.2.3.4", "body_text": "test"}
        result = migrate_payload(payload)
        assert "domain" not in result
        assert "ip" not in result
        assert result["domains"] == ["evil.com"]
        assert result["ips"] == ["1.2.3.4"]

    def test_wrap_scalar_in_list(self):
        payload = {"url": "http://evil.com", "body_text": "test"}
        result = migrate_payload(payload)
        assert isinstance(result["urls"], list)
        assert result["urls"] == ["http://evil.com"]

    def test_keep_plural_unchanged(self):
        payload = {"domains": ["a.com", "b.com"], "body_text": "test"}
        result = migrate_payload(payload)
        assert result["domains"] == ["a.com", "b.com"]

    def test_merge_singular_and_plural(self):
        payload = {"domain": "a.com", "domains": ["b.com"], "body_text": "test"}
        result = migrate_payload(payload)
        assert "domain" not in result
        assert "a.com" in result["domains"]
        assert "b.com" in result["domains"]

    def test_add_schema_version(self):
        payload = {"body_text": "test"}
        result = migrate_payload(payload)
        assert result["schema_version"] == "2.0"

    def test_add_extraction_date(self):
        payload = {"body_text": "test"}
        result = migrate_payload(payload)
        assert "extraction_date" in result
        assert result["extraction_date"] is not None

    def test_rename_text_to_body_text(self):
        payload = {"text": "some content"}
        result = migrate_payload(payload)
        assert "text" not in result
        assert result["body_text"] == "some content"

    def test_rename_content_to_body_text(self):
        payload = {"content": "some content"}
        result = migrate_payload(payload)
        assert "content" not in result
        assert result["body_text"] == "some content"

    def test_keep_body_text_if_present(self):
        payload = {"body_text": "existing"}
        result = migrate_payload(payload)
        assert result["body_text"] == "existing"

    def test_chunk_index_to_int(self):
        payload = {"body_text": "test", "chunk_index": "5"}
        result = migrate_payload(payload)
        assert result["chunk_index"] == 5
        assert isinstance(result["chunk_index"], int)

    def test_all_renames_covered(self):
        expected_renames = {
            "domain": "domains",
            "ip": "ips",
            "url": "urls",
            "email": "emails",
            "cve": "cves",
            "md5": "md5_hashes",
            "sha256": "sha256_hashes",
        }
        for old, new in expected_renames.items():
            assert FIELD_RENAMES[old] == new

    def test_no_change_for_already_migrated(self):
        payload = {
            "body_text": "test",
            "domains": ["a.com"],
            "ips": ["1.2.3.4"],
            "schema_version": "2.0",
            "extraction_date": "2024-01-01T00:00:00Z",
            "chunk_index": 0,
        }
        result = migrate_payload(payload)
        # Should be identical (no renames needed)
        assert result == payload
