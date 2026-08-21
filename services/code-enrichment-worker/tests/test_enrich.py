from unittest.mock import patch

from fastapi.testclient import TestClient

from code_enrichment_worker.main import app


def test_enrich_degraded_without_endpoint(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")

    plan_payload = {"ok": True, "exit_code": 0, "data": {"cwe_ids": ["CWE-89"]}, "error": None}

    monkeypatch.setenv("CODE_ENRICHMENT_ENABLE_KAFKA", "false")
    with (
        patch("code_enrichment_worker.enrich.antares_cli.run_plan", return_value=plan_payload) as plan,
        patch("code_enrichment_worker.enrich.antares_cli.run_tool_query") as query,
        patch("code_enrichment_worker.enrich.post_enrichment_finding") as persist,
        patch("code_enrichment_worker.enrich.settings.antares_endpoint", ""),
    ):
        persist.return_value = {"ok": True, "finding_id": "finding-enrich-test", "status_code": 201}
        from code_enrichment_worker.enrich import enrich_code

        result = enrich_code(
            {
                "tenant_id": "t1",
                "repo_path": str(repo),
                "asset_id": "repo-1",
            }
        )

    plan.assert_called_once()
    query.assert_not_called()
    assert result["human_review_required"] is True
    assert result["autonomous_remediation"] is False
    assert "CWE-89" in result["cwe_ids"]
    assert result["enrichment"]["degraded"] is True
    assert result["enrichment"]["model_ran"] is False
    persist.assert_called_once()
    assert persist.call_args.kwargs["cwe_ids"] == ["CWE-89"]


def test_enrich_runs_tool_when_endpoint_and_cwes(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "db.py").write_text("q = 'select'\n", encoding="utf-8")

    tool_payload = {
        "ok": True,
        "exit_code": 0,
        "data": {
            "findings": [
                {
                    "title": "SQLi lead",
                    "file_path": "db.py",
                    "cwe_ids": ["CWE-89"],
                    "confidence": 0.9,
                }
            ]
        },
        "error": None,
    }

    with (
        patch("code_enrichment_worker.enrich.antares_cli.run_plan") as plan,
        patch("code_enrichment_worker.enrich.antares_cli.run_tool_query", return_value=tool_payload) as query,
        patch("code_enrichment_worker.enrich.post_enrichment_finding") as persist,
        patch("code_enrichment_worker.enrich.settings.antares_endpoint", "http://antares:8000/v1"),
    ):
        persist.return_value = {"ok": True, "finding_id": "f-1", "status_code": 201}
        from code_enrichment_worker.enrich import enrich_code

        result = enrich_code(
            {
                "tenant_id": "t1",
                "repo_path": str(repo),
                "cwe_ids": ["CWE-89"],
                "finding_id": "f-1",
            }
        )

    plan.assert_not_called()
    query.assert_called_once()
    assert result["enrichment"]["model_ran"] is True
    assert result["evidence_refs"]
    assert result["status"] == "completed"


def test_http_enrich_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("CODE_ENRICHMENT_ENABLE_KAFKA", "false")
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "x.py").write_text("x=1\n", encoding="utf-8")

    with (
        patch("code_enrichment_worker.main.consumer.start"),
        patch("code_enrichment_worker.main.consumer.stop"),
        patch("code_enrichment_worker.enrich.antares_cli.run_plan", return_value={"ok": True, "data": {"cwe_ids": ["CWE-22"]}}),
        patch("code_enrichment_worker.enrich.settings.antares_endpoint", ""),
        patch(
            "code_enrichment_worker.enrich.post_enrichment_finding",
            return_value={"ok": True, "finding_id": "fx", "status_code": 201},
        ),
    ):
        client = TestClient(app)
        resp = client.post(
            "/api/v1/code/enrich",
            json={"tenant_id": "default", "repo_path": str(repo)},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["human_review_required"] is True
        assert "CWE-22" in body["cwe_ids"]

        live = client.get("/health/live")
        assert live.status_code == 200
        assert live.json()["status"] == "alive"
