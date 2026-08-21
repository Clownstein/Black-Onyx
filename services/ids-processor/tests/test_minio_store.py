"""Unit tests for MinIO PCAP helper (offline — no live MinIO required)."""

from ids_processor.minio_store import build_uri, evidence_ref_for_pcap, parse_uri


def test_parse_and_build_uri():
    uri = build_uri("anomaly-pcap", "pcap/host-1/alert.pcap")
    assert uri.startswith("s3://anomaly-pcap/pcap/host-1/alert.pcap")
    bucket, key = parse_uri(uri)
    assert bucket == "anomaly-pcap"
    assert key == "pcap/host-1/alert.pcap"


def test_evidence_ref_records_without_boto3(monkeypatch):
    monkeypatch.setattr("ids_processor.minio_store._client", lambda: None)
    ref = evidence_ref_for_pcap(b"\xd4\xc3\xb2\xa1", asset_id="host-web-01", alert_id=2100498)
    assert ref["type"] == "pcap"
    assert ref["uploaded"] is False
    assert ref["sha256"]
    assert "pcap/host-web-01/" in ref["uri"]
