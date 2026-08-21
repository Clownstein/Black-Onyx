import pytest
from httpx import ASGITransport, AsyncClient

from integration_hub.main import app
from integration_hub.siem import format_siem_export, incident_to_cef
from integration_hub.vuln import extract_vulnerabilities, vulnerability_to_finding


def test_extract_trivy():
    report = {
        "Results": [
            {
                "Target": "app/Dockerfile",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "Severity": "HIGH",
                        "Title": "OpenSSL issue",
                    }
                ],
            }
        ]
    }
    rows = extract_vulnerabilities(report)
    assert len(rows) == 1
    finding = vulnerability_to_finding(
        rows[0], tenant_id="t1", asset_id="img-1", kev_boost=True
    )
    assert finding["finding_type"] == "vulnerability"
    assert finding["asset_id"] == "img-1"
    assert finding["context"]["cve"] == "CVE-2024-1234"
    assert finding["context"]["kev"] is True
    assert finding["calibrated_score"] >= 0.8


def test_extract_grype():
    report = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2023-9999",
                    "severity": "critical",
                    "description": "bad",
                },
                "artifact": {"name": "curl", "version": "7.0"},
            }
        ]
    }
    rows = extract_vulnerabilities(report)
    assert rows[0]["_scanner"] == "grype"
    finding = vulnerability_to_finding(rows[0], tenant_id="t1", asset_id="host-9")
    assert finding["context"]["cve"] == "CVE-2023-9999"


def test_siem_json_and_cef():
    incident = {
        "incident_id": "inc-1",
        "tenant_id": "t1",
        "title": "Lateral movement",
        "severity": "high",
        "risk_score": 0.82,
        "asset_ids": ["a1", "a2"],
        "mitre_techniques": ["T1021"],
        "status": "open",
        "summary": "Suspicious RDP",
    }
    js = format_siem_export(incident, fmt="json")
    assert js["format"] == "json"
    assert js["incident"]["incident_id"] == "inc-1"
    cef = incident_to_cef(incident)
    assert cef.startswith("CEF:0|BlackOnyx|integration-hub|")
    assert "externalId=inc-1" in cef
    assert "cs3=T1021" in cef


@pytest.mark.asyncio
async def test_vuln_ingest_endpoint(monkeypatch):
    async def fake_match(cves):
        return {"CVE-2024-1234": {"type": "cve", "value": "CVE-2024-1234", "source": "cisa-kev"}}

    async def fake_persist(findings):
        assert len(findings) == 1
        return {"enabled": True, "persisted": 1, "failed": 0}

    monkeypatch.setattr("integration_hub.main.match_cves", fake_match)
    monkeypatch.setattr("integration_hub.main.persist_findings", fake_persist)
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-API-Key": "dev-integration-key"},
    ) as client:
        response = await client.post(
            "/api/v1/vuln/ingest",
            json={
                "asset_id": "registry/app:1",
                "tenant_id": "t1",
                "report": {
                    "Results": [
                        {
                            "Target": "app",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2024-1234",
                                    "PkgName": "libx",
                                    "Severity": "MEDIUM",
                                }
                            ],
                        }
                    ]
                },
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["findings_count"] == 1
    assert data["kev_boosted"] == 1
    assert data["findings"][0]["context"]["kev"] is True
    assert data["persist"]["persisted"] == 1


@pytest.mark.asyncio
async def test_siem_export_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-API-Key": "dev-integration-key"},
    ) as client:
        response = await client.post(
            "/api/v1/integrations/siem/export",
            json={
                "format": "cef",
                "incident": {
                    "incident_id": "inc-9",
                    "title": "Beaconing",
                    "severity": "critical",
                    "summary": "C2",
                },
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "cef"
    assert "CEF:0|" in data["cef"]
