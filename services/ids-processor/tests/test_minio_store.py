"""Unit tests for MinIO PCAP helper (offline no live MinIO required)."""

import hashlib

from ids_processor.minio_store import build_uri, evidence_ref_for_pcap, parse_uri

PCAP = b"\xd4\xc3\xb2\xa1excerpt"


class RecordingS3:
    def __init__(self):
        self.objects = {}

    def head_bucket(self, Bucket):
        return {}

    def put_object(self, Bucket, Key, Body, ContentType, Metadata):
        self.objects[(Bucket, Key)] = Body


def test_parse_and_build_uri_has_no_query():
    uri = build_uri("black-onyx-pcap", "pcap/tenant-a/host-1/alert.pcap")
    assert uri == "s3://black-onyx-pcap/pcap/tenant-a/host-1/alert.pcap"
    assert parse_uri(uri) == ("black-onyx-pcap", "pcap/tenant-a/host-1/alert.pcap")


def test_evidence_ref_is_tenant_scoped_and_uploaded(monkeypatch):
    s3 = RecordingS3()
    monkeypatch.setattr("ids_processor.minio_store._client", lambda: s3)
    ref = evidence_ref_for_pcap(PCAP, tenant_id="tenant-a", asset_id="host web/01", alert_id=2100498)
    digest = hashlib.sha256(PCAP).hexdigest()
    key = f"pcap/tenant-a/host_web_01/2100498-{digest[:16]}.pcap"
    assert ref["uri"] == f"s3://black-onyx-pcap/{key}"
    assert ref["sha256"] == digest
    assert s3.objects[("black-onyx-pcap", key)] == PCAP


def test_no_evidence_ref_when_upload_impossible(monkeypatch):
    monkeypatch.setattr("ids_processor.minio_store._client", lambda: None)
    assert evidence_ref_for_pcap(PCAP, tenant_id="tenant-a", asset_id="h", alert_id=1) is None


def test_no_evidence_ref_for_unsafe_tenant(monkeypatch):
    monkeypatch.setattr("ids_processor.minio_store._client", lambda: RecordingS3())
    assert evidence_ref_for_pcap(PCAP, tenant_id="../other", asset_id="h") is None
