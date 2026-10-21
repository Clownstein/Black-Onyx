import json
from unittest.mock import patch

from code_enrichment_worker import antares_cli


def test_run_plan_uses_subprocess(monkeypatch):
    calls: list[dict] = []

    def fake_run(cmd, **kwargs):
        calls.append({"cmd": cmd, "kwargs": kwargs})

        class Result:
            returncode = 0
            stdout = '{"cwe_ids":["CWE-89"]}'
            stderr = ""

        return Result()

    monkeypatch.setattr(antares_cli.subprocess, "run", fake_run)
    monkeypatch.setattr(antares_cli.shutil, "which", lambda _: None)

    result = antares_cli.run_plan("/tmp/repo")
    assert result["ok"] is True
    assert result["data"]["cwe_ids"] == ["CWE-89"]
    assert calls[0]["cmd"][:3] == ["python", "-m", "antares_cli"]
    assert "plan" in calls[0]["cmd"]
    assert "--format" in calls[0]["cmd"]
    assert "json" in calls[0]["cmd"]


def test_run_tool_query_stdin(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input")

        class Result:
            returncode = 0
            stdout = '{"findings":[{"file_path":"a.py","cwe_ids":["CWE-78"],"title":"cmd"}]}'
            stderr = ""

        return Result()

    monkeypatch.setattr(antares_cli.subprocess, "run", fake_run)
    monkeypatch.setattr(antares_cli.shutil, "which", lambda _: "/usr/bin/antares")

    with patch.object(antares_cli.settings, "antares_endpoint", "http://antares:8000"):
        result = antares_cli.run_tool_query("/tmp/repo", ["CWE-78"])

    assert result["ok"] is True
    assert captured["cmd"][0] == "/usr/bin/antares"
    assert "query" in captured["cmd"]
    assert "--stdin" in captured["cmd"]
    assert "CWE-78" in (captured["input"] or "")


def test_tool_invocations_forward_served_model_with_endpoint(monkeypatch):
    captured: list[dict] = []

    def fake_run(cmd, **kwargs):
        captured.append({"input": json.loads(kwargs["input"]), "env": kwargs["env"]})

        class Result:
            returncode = 0
            stdout = "{}"
            stderr = ""

        return Result()

    monkeypatch.setattr(antares_cli.subprocess, "run", fake_run)
    monkeypatch.setattr(antares_cli.shutil, "which", lambda _: "/usr/bin/antares")
    monkeypatch.delenv("ANTARES_MODEL", raising=False)

    with patch.object(antares_cli.settings, "antares_endpoint", "http://vllm-antares:8000"):
        antares_cli.run_tool_query("/tmp/repo", ["CWE-78"])
        antares_cli.run_tool_sweep("/tmp/repo")

    for call in captured:
        assert call["input"]["model"] == "antares-1b"
        assert call["env"]["ANTARES_MODEL"] == "antares-1b"

    captured.clear()
    with patch.object(antares_cli.settings, "antares_endpoint", ""):
        antares_cli.run_tool_query("/tmp/repo", ["CWE-78"])
    assert "model" not in captured[0]["input"]
    assert "ANTARES_MODEL" not in captured[0]["env"]
