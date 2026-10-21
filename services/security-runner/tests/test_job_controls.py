"""Per-session job cap, workspace quota, cancellation and read-only mounts."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import security_runner.app as runner_app
from security_runner.app import Execution, _container_options

SESSION = "f" * 64 + "/work"
PINNED = "ghcr.io/example/sandbox@sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def clean_registry(monkeypatch, tmp_path):
    monkeypatch.setenv("SESSIONS_ROOT", str(tmp_path))
    monkeypatch.setattr(runner_app, "_host_sessions_root", lambda: tmp_path)
    runner_app._jobs.clear()
    runner_app._session_counts.clear()
    yield
    runner_app._jobs.clear()
    runner_app._session_counts.clear()


def job(**overrides) -> Execution:
    base = dict(session=SESSION, tool="Read", argv=["sed", "-n", "1,5p", "--", "a.txt"], timeout=30)
    base.update(overrides)
    return Execution(**base)


def test_per_session_concurrency_cap(monkeypatch):
    monkeypatch.setenv("SECURITY_RUNNER_MAX_JOBS_PER_SESSION", "2")
    first = runner_app._register_job(job())
    runner_app._register_job(job())
    with pytest.raises(HTTPException) as exc:
        runner_app._register_job(job())
    assert exc.value.status_code == 429
    # Another session is unaffected.
    runner_app._register_job(job(session="e" * 64 + "/work"))
    runner_app._release_job(first)
    runner_app._register_job(job())


def test_duplicate_job_id_rejected():
    runner_app._register_job(job(job_id="job-abcdefgh"))
    with pytest.raises(HTTPException) as exc:
        runner_app._register_job(job(job_id="job-abcdefgh"))
    assert exc.value.status_code == 409


def test_workspace_quota(monkeypatch, tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "big.bin").write_bytes(b"x" * 2048)
    monkeypatch.setenv("SECURITY_RUNNER_WORKSPACE_QUOTA_BYTES", "1024")
    with pytest.raises(HTTPException) as exc:
        runner_app._check_quota(workspace)
    assert exc.value.status_code == 507
    monkeypatch.setenv("SECURITY_RUNNER_WORKSPACE_QUOTA_BYTES", "0")
    runner_app._check_quota(workspace)  # 0 disables the quota


def test_run_binary_uses_dot_slash_for_workspace_files(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "hello").write_bytes(b"\x7fELF")
    job_spec = job(tool="run_binary", argv=["timeout", "30", "hello"])
    runner_app._rewrite_run_binary_path(job_spec, workspace)
    assert job_spec.argv[2] == "./hello"
    path_job = job(tool="run_binary", argv=["timeout", "30", "whoami"])
    runner_app._rewrite_run_binary_path(path_job, workspace)
    assert path_job.argv[2] == "whoami"


def test_read_tools_get_read_only_mount(tmp_path):
    for tool, argv in (("Read", ["sed", "-n", "1p", "--", "a"]), ("hash_data", ["python3", "-c", "x", "sha256"])):
        options = _container_options(job(tool=tool, argv=argv), PINNED, tmp_path)
        assert options["volumes"][str(tmp_path)]["mode"] == "ro", tool
    write = _container_options(job(tool="Write", argv=["python3", "-c", "x", "a"]), PINNED, tmp_path)
    assert write["volumes"][str(tmp_path)]["mode"] == "rw"


class FakeContainer:
    def __init__(self):
        self.killed = False

    def kill(self):
        self.killed = True


def test_cancel_requires_auth_and_owning_session(monkeypatch):
    monkeypatch.setenv("SECURITY_RUNNER_TOKEN", "runner-token")
    client = TestClient(runner_app.app)
    job_id = runner_app._register_job(job(job_id="job-cancel01"))
    container = FakeContainer()
    runner_app._jobs[job_id]["container"] = container
    assert client.post(f"/jobs/{job_id}/cancel", json={"session": SESSION}).status_code == 401
    headers = {"Authorization": "Bearer runner-token"}
    other = client.post(f"/jobs/{job_id}/cancel", json={"session": "e" * 64 + "/work"}, headers=headers)
    assert other.status_code == 404
    ok = client.post(f"/jobs/{job_id}/cancel", json={"session": SESSION}, headers=headers)
    assert ok.status_code == 200
    assert container.killed and runner_app._jobs[job_id]["cancelled"]


def test_capability_probe_is_hardened_and_cached(monkeypatch):
    monkeypatch.setenv("SECURITY_RUNNER_TOKEN", "runner-token")
    monkeypatch.setenv("SECURITY_SANDBOX_IMAGE", PINNED)
    runner_app._capability_cache.clear()
    calls = []

    def fake_probe(options):
        calls.append(options)
        return {req: req == "bin:strings" for req in options["command"][3:]}

    monkeypatch.setattr(runner_app, "_run_probe", fake_probe)
    client = TestClient(runner_app.app)
    headers = {"Authorization": "Bearer runner-token"}
    assert client.post("/capabilities", json={"requirements": ["bin:strings"]}).status_code == 401
    bad = client.post("/capabilities", json={"requirements": ["bin:x; rm -rf /"]}, headers=headers)
    assert bad.status_code == 400
    first = client.post("/capabilities", json={"requirements": ["bin:strings", "py:pwn"]}, headers=headers)
    assert first.status_code == 200
    assert first.json()["requirements"] == {"bin:strings": True, "py:pwn": False}
    client.post("/capabilities", json={"requirements": ["py:pwn", "bin:strings"]}, headers=headers)
    assert len(calls) == 1
    options = calls[0]
    assert options["network_mode"] == "none" and options["read_only"] is True
    assert options["cap_drop"] == ["ALL"] and "volumes" not in options
    assert options["environment"]["PATH"].startswith("/opt/blackonyx/bin:")


def test_capability_probe_attests_readonly_image_helpers(monkeypatch):
    from security_runner.app import ProbeRequest, PROBE_SCRIPT

    requirement = "helper:anvil_send.py"
    assert ProbeRequest(requirements=[requirement]).validated() == (requirement,)
    compile(PROBE_SCRIPT, "<capability-probe>", "exec")
    options = runner_app._probe_options(PINNED, (requirement,))
    assert options["environment"]["PATH"].startswith("/opt/blackonyx/bin:")
    assert options["command"][-1] == requirement
