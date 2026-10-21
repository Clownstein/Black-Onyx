"""Sandbox isolation invariants for the security runner.

`test_auth.py` covers who may call `/execute`. These cover what `/execute` is
allowed to build once the caller is authenticated: the image must be pinned,
the workspace must stay inside SESSIONS_ROOT, unknown tools must fail closed,
and every container option that keeps a security tool inside its sandbox must
survive refactors of `_container_options`.

Nothing here starts a container. They assert on the options dict the runner
hands to Docker, which is where the isolation actually lives.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from security_runner.app import (
    Execution,
    _container_options,
    _resolve_workspace,
    _validate_image,
)
import security_runner.app as runner_app

PINNED = "ghcr.io/example/sandbox@sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def session_roots(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("SESSIONS_ROOT", str(tmp_path))
    monkeypatch.setattr(runner_app, "_host_sessions_root", lambda: tmp_path)


def job(**overrides) -> Execution:
    base = dict(
        session="f" * 64 + "/work",
        tool="Bash",
        argv=["/bin/sh", "-c", "echo hi"],
        timeout=30,
    )
    base.update(overrides)
    return Execution(**base)


# ── Image pinning ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "image",
    [
        "",
        "ubuntu:22.04",
        "ghcr.io/example/sandbox:latest",
        "ghcr.io/example/sandbox@sha256:short",
        "sha256:" + "a" * 63,
        "ghcr.io/example/sandbox@md5:" + "a" * 64,
    ],
)
def test_unpinned_images_are_refused(monkeypatch, image: str) -> None:
    """A tag can be repointed after review; a digest cannot."""
    monkeypatch.setenv("SECURITY_SANDBOX_IMAGE", image)
    with pytest.raises(HTTPException) as excinfo:
        _validate_image()
    assert excinfo.value.status_code == 503


def test_digest_pinned_image_is_accepted(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_SANDBOX_IMAGE", PINNED)
    assert _validate_image() == PINNED


def test_local_image_id_matches_configured_digest() -> None:
    digest = "sha256:" + "b" * 64
    ref = f"blackonyx-security-toolbox@{digest}"

    class _Images:
        def get(self, name: str):
            if name == ref:
                raise Exception("not a registry digest")
            if name != digest:
                raise Exception(name)
            return type("Img", (), {"id": digest, "attrs": {"Id": digest, "RepoDigests": []}})()

    client = type("Client", (), {"images": _Images()})()
    assert runner_app._resolved_image_id(client, ref) == digest


def test_missing_image_env_is_refused(monkeypatch) -> None:
    monkeypatch.delenv("SECURITY_SANDBOX_IMAGE", raising=False)
    with pytest.raises(HTTPException) as excinfo:
        _validate_image()
    assert excinfo.value.status_code == 503


# ── Filesystem isolation ──────────────────────────────────────────────────


def test_session_pattern_rejects_traversal_and_absolute_paths() -> None:
    """The session field is the only caller-supplied part of the path."""
    for bad in [
        "../../etc",
        "f" * 64 + "/../../etc",
        "f" * 64 + "/..",
        "/etc/passwd",
        "F" * 64 + "/work",  # uppercase hex is not the digest shape
        "f" * 63 + "/work",
        "f" * 64 + "/.hidden",
        "f" * 64 + "/a/b",
    ]:
        with pytest.raises(Exception):
            job(session=bad)


def test_workspace_must_exist_under_sessions_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "sessions"
    (root / ("f" * 64) / "work").mkdir(parents=True)
    monkeypatch.setenv("SESSIONS_ROOT", str(root))

    resolved = _resolve_workspace("f" * 64 + "/work")
    assert resolved == (root / ("f" * 64) / "work").resolve()


def test_missing_workspace_is_refused(monkeypatch, tmp_path) -> None:
    root = tmp_path / "sessions"
    root.mkdir()
    monkeypatch.setenv("SESSIONS_ROOT", str(root))

    with pytest.raises(HTTPException) as excinfo:
        _resolve_workspace("f" * 64 + "/work")
    assert excinfo.value.status_code == 400


def test_symlinked_workspace_is_refused(monkeypatch, tmp_path) -> None:
    """A symlink inside SESSIONS_ROOT would otherwise bind a host directory."""
    root = tmp_path / "sessions"
    (root / ("f" * 64)).mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / ("f" * 64) / "work"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this host")
    monkeypatch.setenv("SESSIONS_ROOT", str(root))

    with pytest.raises(HTTPException) as excinfo:
        _resolve_workspace("f" * 64 + "/work")
    assert excinfo.value.status_code == 400


# ── Capability allowlist fails closed ─────────────────────────────────────


def test_unknown_tool_is_refused(tmp_path) -> None:
    """Neither offline nor network-listed: the runner must not guess."""
    with pytest.raises(HTTPException) as excinfo:
        _container_options(job(tool="curl_anything"), PINNED, tmp_path)
    assert excinfo.value.status_code == 503


def test_offline_tool_gets_no_network(tmp_path) -> None:
    options = _container_options(job(tool="extract_strings"), PINNED, tmp_path)
    assert options["network_mode"] == "none"


def test_network_profile_fails_closed_without_enforced_egress(tmp_path) -> None:
    with pytest.raises(HTTPException) as offline_error:
        _container_options(job(tool="nmap_scan"), PINNED, tmp_path)
    assert offline_error.value.status_code == 400

    with pytest.raises(HTTPException) as excinfo:
        _container_options(job(tool="nmap_scan", network_profile="public"), PINNED, tmp_path)
    assert excinfo.value.status_code == 503


def test_network_profile_rejects_unknown_values() -> None:
    with pytest.raises(Exception):
        job(network_profile="host")


# ── Environment allowlist ─────────────────────────────────────────────────


def test_environment_is_refused_for_tools_with_no_allowlist(tmp_path) -> None:
    with pytest.raises(HTTPException) as excinfo:
        _container_options(
            job(tool="Bash", environment={"AWS_SECRET_ACCESS_KEY": "x"}), PINNED, tmp_path
        )
    assert excinfo.value.status_code == 400


def test_provider_secrets_never_enter_sandbox_environment(tmp_path) -> None:
    with pytest.raises(HTTPException):
        _container_options(
            job(tool="shodan_search", environment={"SHODAN_API_KEY": "k"}),
            PINNED,
            tmp_path,
        )


def test_oversized_and_nul_environment_values_are_refused(tmp_path) -> None:
    for value in ["x" * 4097, "ok\x00injected"]:
        with pytest.raises(HTTPException):
            _container_options(
                job(tool="Bash", environment={"UNTRUSTED_VALUE": value}),
                PINNED,
                tmp_path,
            )


def test_environment_count_is_bounded() -> None:
    with pytest.raises(Exception):
        job(environment={f"K{i}": "v" for i in range(5)})


# ── Container hardening ───────────────────────────────────────────────────


def test_container_options_keep_every_hardening_flag(tmp_path) -> None:
    """One assertion per property that stands between a tool and the host."""
    options = _container_options(job(), PINNED, tmp_path)

    assert options["image"] == PINNED
    assert options["user"] == "10001:10001", "must not run as root"
    assert options["read_only"] is True, "root filesystem must not be writable"
    assert options["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in options["security_opt"]
    assert options["pids_limit"] == 50
    assert options["mem_limit"] == "1g"
    assert options["nano_cpus"] == 1_000_000_000
    assert options["init"] is True, "PID 1 reaping keeps zombies out of the sandbox"
    assert options["stdin_open"] is False
    assert options["entrypoint"] == [], "the image entrypoint must not be re-added"

    tmpfs = options["tmpfs"]["/tmp"]
    for flag in ("noexec", "nosuid", "nodev"):
        assert flag in tmpfs, f"/tmp is missing {flag}"

    # The session workspace is the only host path bound in, and only itself.
    assert list(options["volumes"]) == [str(tmp_path)]
    assert options["volumes"][str(tmp_path)]["bind"] == str(tmp_path)


def test_container_path_is_not_inherited_from_the_host(tmp_path) -> None:
    options = _container_options(job(), PINNED, tmp_path)
    assert options["environment"]["PATH"] == "/opt/blackonyx/bin:/usr/local/bin:/usr/bin:/bin"
    assert options["environment"]["HOME"] == "/tmp"
    assert options["environment"]["TERM"] == "dumb"


def test_logs_are_capped_so_a_tool_cannot_fill_the_host(tmp_path) -> None:
    options = _container_options(job(), PINNED, tmp_path)
    assert options["log_config"]["Config"]["max-size"] == "1m"
    assert options["log_config"]["Config"]["max-file"] == "1"


def test_containers_are_labelled_for_reaping(tmp_path) -> None:
    """Cleanup runs in `execute`'s finally block; the label is the backstop."""
    options = _container_options(job(), PINNED, tmp_path)
    assert options["labels"]["black-onyx.runner"] == "tool"


# ── Request bounds ────────────────────────────────────────────────────────


def test_timeout_is_bounded() -> None:
    job(timeout=1)
    job(timeout=300)
    for bad in [0, -1, 301, 86400]:
        with pytest.raises(Exception):
            job(timeout=bad)


def test_command_length_is_bounded() -> None:
    with pytest.raises(Exception):
        job(argv=["a" for _ in range(101)])
    with pytest.raises(Exception):
        job(argv=[])


def test_unknown_request_fields_are_rejected() -> None:
    """`extra="forbid"` stops a caller smuggling an option into Docker."""
    with pytest.raises(Exception):
        job(privileged=True)
