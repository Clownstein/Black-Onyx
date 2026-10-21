"""incident-api accepts the evidence URIs other services actually produce."""

import pytest

from incident_api import minio_evidence


@pytest.fixture(autouse=True)
def _buckets(monkeypatch):
    monkeypatch.setattr(minio_evidence.settings, "evidence_buckets", "black-onyx-malware,black-onyx-pcap")


@pytest.mark.parametrize(
    "uri",
    [
        # ids-processor PCAP excerpt
        "s3://black-onyx-pcap/pcap/tenant-a/host-web-01/2100498-0123456789abcdef.pcap",
        # malware-triage static report
        "s3://black-onyx-malware/reports/tenant-a/" + "a" * 64 + ".json",
    ],
)
def test_producer_uris_are_downloadable_for_their_tenant(uri):
    assert minio_evidence.validate_tenant_evidence_uri(uri, "tenant-a")


@pytest.mark.parametrize(
    "uri",
    [
        "s3://black-onyx-pcap/pcap/tenant-b/host/x.pcap",
        "s3://black-onyx-pcap/pcap/tenant-a/host/x.pcap?endpoint=http://minio:9000",
        "s3://other-bucket/pcap/tenant-a/host/x.pcap",
        "s3://black-onyx-malware/samples/tenant-a/" + "a" * 64 + ".bin",
        "s3://black-onyx-pcap/pcap/tenant-a/../tenant-b/x.pcap",
    ],
)
def test_foreign_or_malformed_uris_are_refused(uri):
    with pytest.raises(ValueError):
        minio_evidence.validate_tenant_evidence_uri(uri, "tenant-a")
