from threat_intel_service.ingest.stix_upload import extract_observables_from_pattern, ingest_stix_bundle
from threat_intel_service.store import match_observables


def test_extract_ipv4_domain_url_hash() -> None:
    pattern = (
        "[ipv4-addr:value = '198.51.100.10'] OR "
        "[domain-name:value = 'bad.example'] OR "
        "[url:value = 'https://bad.example/path'] OR "
        "[file:hashes.'SHA-256' = 'ABCDEF']"
    )
    obs = extract_observables_from_pattern(pattern)
    assert ("ipv4", "198.51.100.10") in obs
    assert ("domain", "bad.example") in obs
    assert ("url", "https://bad.example/path") in obs
    assert ("file_hash", "abcdef") in obs


def test_ingest_stix_bundle(db_session) -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--aaa",
                "pattern": "[ipv4-addr:value = '203.0.113.50']",
                "confidence": 90,
                "labels": ["tlp:amber", "malicious-activity"],
                "valid_from": "2024-01-01T00:00:00Z",
            },
            {"type": "malware", "id": "malware--bbb", "name": "ignored"},
            {
                "type": "indicator",
                "id": "indicator--ccc",
                "pattern": "[domain-name:value = 'phish.example']",
                "external_references": [{"source_name": "otx"}],
            },
        ],
    }
    result = ingest_stix_bundle(db_session, bundle)
    assert result["upserted"] == 2
    hits = match_observables(db_session, [{"type": "ipv4", "value": "203.0.113.50"}])
    assert len(hits) == 1
    assert hits[0].tlp == "amber"
    assert hits[0].confidence == 90
    domain_hits = match_observables(db_session, [{"type": "domain", "value": "phish.example"}])
    assert domain_hits[0].source == "otx"
