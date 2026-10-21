"""Docker-owning runner for security tool execution.

Merged from model-tools/runner/app.py. Network capabilities fail closed.
The fixed image and host sessions root are operator configuration, never
request parameters. Deploy this service only on an isolated authenticated
control network (black-onyx-runner).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import stat
import threading
from pathlib import Path, PureWindowsPath
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from security_runner.egress_policy import extra_hosts

logger = logging.getLogger(__name__)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
slots = asyncio.Semaphore(4)

# Tools that never modify the workspace get a read-only mount. Input for
# stdin-driven tools is staged by the runner, not written by the container.
# Keep in sync with security_gateway.execution_spec.READ_ONLY_TOOLS.
READ_ONLY_TOOLS = frozenset({
    "Read", "Grep", "Glob", "ListFiles", "checksec", "decompile",
    "decompile_function", "disassemble", "disassemble_binary",
    "extract_strings", "file_info", "search_gadgets", "analyze_pcap",
    "cast_keccak", "aes_encrypt", "aes_decrypt", "decode_hex",
    "encode_base64", "decode_base64", "hash_data", "extract_iocs",
    "compute_threat_score", "cyclic_pattern",
    "generate_yara_rule",
})


def _int_env(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


# Running jobs: job_id -> session, tool/guard containers, cancellation, and policy path.
_jobs: dict[str, dict] = {}
_session_counts: dict[str, int] = {}
_jobs_lock = threading.Lock()

NETWORK_CONTAINER_TOOLS = frozenset({
    "nmap_scan", "port_scan", "sqlmap_scan", "nikto_scan", "whois_lookup",
    "gobuster_dir", "hydra_brute", "cast_call", "get_contract_storage", "cast_send",
})


def _read_secret(name: str) -> str:
    """Read a secret from env or its _FILE variant (64 KiB max)."""
    val = os.environ.get(name, "")
    if val:
        return val
    file_path = os.environ.get(f"{name}_FILE", "")
    if file_path:
        try:
            return Path(file_path).read_text(errors="replace")[:65536].strip()
        except OSError:
            return ""
    return ""


class Execution(BaseModel):
    """A single sandboxed execution request."""
    model_config = ConfigDict(extra="forbid", strict=True)
    session: str = Field(pattern=r"^[a-f0-9]{64}/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    tool: str = Field(min_length=1, max_length=64)
    argv: list[str] = Field(min_length=1, max_length=100)
    stdin: str = Field(default="", max_length=100000)
    timeout: int = Field(ge=1, le=300)
    environment: dict[str, str] = Field(default_factory=dict, max_length=4)
    network_profile: Literal["offline", "public", "lab"] = "offline"
    destinations: list[str] = Field(default_factory=list, max_length=100)
    ports: list[int] = Field(default_factory=list, max_length=64)
    lab_profile_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    resolved_targets: dict[str, list[str]] = Field(default_factory=dict, max_length=100)
    job_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{8,64}$")


class CancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    session: str = Field(pattern=r"^[a-f0-9]{64}/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _workspace_bytes(workspace: Path) -> int:
    """Total size of regular files under the workspace (symlinks not followed)."""
    total = 0
    stack = [workspace]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
        except OSError:
            continue
    return total


def _check_quota(workspace: Path) -> None:
    quota = _int_env("SECURITY_RUNNER_WORKSPACE_QUOTA_BYTES", 1024 * 1024 * 1024)
    if quota and _workspace_bytes(workspace) >= quota:
        raise HTTPException(507, "Session workspace quota exceeded")


def _register_job(job: Execution) -> str:
    """Reserve a per-session slot; returns the job id used for cancellation."""
    job_id = job.job_id or secrets.token_hex(12)
    limit = _int_env("SECURITY_RUNNER_MAX_JOBS_PER_SESSION", 2)
    with _jobs_lock:
        if job_id in _jobs:
            raise HTTPException(409, "Job id is already running")
        if limit and _session_counts.get(job.session, 0) >= limit:
            raise HTTPException(429, "Too many concurrent jobs for this session")
        _session_counts[job.session] = _session_counts.get(job.session, 0) + 1
        _jobs[job_id] = {
            "session": job.session, "container": None, "guard": None,
            "policy_dir": None, "cancelled": False,
        }
    return job_id


def _release_job(job_id: str) -> None:
    with _jobs_lock:
        entry = _jobs.pop(job_id, None)
        if entry is not None:
            remaining = _session_counts.get(entry["session"], 1) - 1
            if remaining > 0:
                _session_counts[entry["session"]] = remaining
            else:
                _session_counts.pop(entry["session"], None)


def authorize(authorization: str | None) -> None:
    """Constant-time bearer auth against SECURITY_RUNNER_TOKEN."""
    secret = _read_secret("SECURITY_RUNNER_TOKEN")
    if not secret or not hmac.compare_digest(
        (authorization or "").encode(), (f"Bearer {secret}").encode()
    ):
        raise HTTPException(401, "Authentication required")


@app.middleware("http")
async def authenticate_execution(request: Request, call_next):
    """Reject unauthenticated execution before request-body validation."""
    if request.url.path in {"/execute", "/workspace", "/capabilities", "/network-ready"} or request.url.path.startswith("/jobs/"):
        try:
            authorize(request.headers.get("authorization"))
        except HTTPException:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    return await call_next(request)


def _validate_image() -> str:
    """Require a digest-pinned sandbox image no tag-only fallback."""
    image = os.environ.get("SECURITY_SANDBOX_IMAGE", "")
    if not re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", image):
        raise HTTPException(503, "Runner requires an image pinned by digest")
    return image


def _validate_guard_image() -> str:
    image = os.environ.get("SECURITY_GUARD_IMAGE", "")
    if not re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", image):
        raise HTTPException(503, "Runner requires a digest-pinned egress guard image")
    return image


def _network_policy(job: Execution) -> tuple[str, dict[str, object] | None]:
    """Validate operator registration and return (Docker network, lab profile)."""
    if job.network_profile == "offline":
        if job.destinations or job.ports or job.lab_profile_id or job.resolved_targets:
            raise HTTPException(400, "Offline jobs cannot carry network scope")
        return "", None
    from security_runner.egress_policy import EgressDenied, parse_lab_profiles

    if os.environ.get("SECURITY_EGRESS_VERIFIED", "").lower() != "true":
        raise HTTPException(503, "Per-job egress has not passed its independent verification gate")
    if not _read_secret("SECURITY_GUARD_IMAGE"):
        raise HTTPException(503, "Digest-pinned egress guard image is not configured")
    _validate_guard_image()
    if not job.destinations or not job.ports:
        raise HTTPException(400, "Networked jobs require explicit destinations and TCP ports")
    all_tcp = list(job.ports) == [0]
    if all_tcp:
        pass
    elif any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in job.ports):
        raise HTTPException(400, "Invalid TCP port scope")
    elif len(set(job.ports)) != len(job.ports):
        raise HTTPException(400, "TCP port scope must not contain duplicates")
    if job.network_profile == "public":
        if job.lab_profile_id is not None or os.environ.get("ALLOW_PUBLIC_TARGETS", "").lower() != "true":
            raise HTTPException(403, "Public network execution is not enabled")
        network = os.environ.get("SECURITY_EGRESS_NETWORK", "")
        if not network:
            raise HTTPException(503, "Dedicated public egress network is not configured")
        return network, None
    if os.environ.get("ALLOW_PRIVATE_TARGETS", "").lower() != "true" or not job.lab_profile_id:
        raise HTTPException(403, "Lab execution requires an enabled, registered lab profile")
    try:
        profiles = parse_lab_profiles(_read_secret("SECURITY_LAB_PROFILES_JSON"))
    except EgressDenied as exc:
        raise HTTPException(503, "Registered lab configuration is invalid") from exc
    profile = profiles.get(job.lab_profile_id)
    if profile is None:
        raise HTTPException(403, "Requested network scope is outside the registered lab profile")
    allowed = profile["ports"]
    if all_tcp:
        if allowed is not None:
            raise HTTPException(403, "Requested network scope is outside the registered lab profile")
    elif allowed is not None and not set(job.ports).issubset(allowed):
        raise HTTPException(403, "Requested network scope is outside the registered lab profile")
    return str(profile["network"]), profile


def _resolve_workspace(session: str) -> Path:
    """Resolve the session workspace under the fixed SESSIONS_ROOT."""
    root = Path(os.environ["SESSIONS_ROOT"]).resolve(strict=True)
    local = root
    for component in session.split("/"):
        local = local / component
        if local.is_symlink() or not local.is_dir():
            raise HTTPException(400, "Invalid workspace")
    return local


class WorkspaceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    session: str = Field(pattern=r"^[a-f0-9]{64}/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@app.post("/workspace")
def provision_workspace(body: WorkspaceRequest, authorization: str | None = Header(None)) -> dict[str, str]:
    authorize(authorization)
    root = Path(os.environ["SESSIONS_ROOT"]).resolve(strict=True)
    if not os.access(root, os.W_OK):
        raise HTTPException(503, "Sessions root is not writable by the runner")
    current = root
    for component in body.session.split("/"):
        current = current / component
        if current.is_symlink():
            raise HTTPException(400, "Invalid workspace")
        current.mkdir(mode=0o700, exist_ok=True)
        if not current.is_dir() or current.is_symlink() or root not in current.resolve().parents:
            raise HTTPException(400, "Invalid workspace")
        if os.name == "posix":
            try:
                if current.stat().st_uid != os.getuid() or os.getuid() != 10001:
                    raise HTTPException(503, "Workspace is not owned by the sandbox user")
                current.chmod(0o700)
            except OSError as exc:
                raise HTTPException(503, "Workspace ownership could not be established") from exc
    return {"status": "ready", "session": body.session}


def _container_options(job: Execution, image: str, workspace: Path) -> dict:
    """Build Docker container options with fail-closed network policy."""

    offline = {
        "Bash", "Read", "Write", "Edit", "Grep", "Glob", "ListFiles",
        "run_binary", "compile_contracts", "analyze_contract",
        "generate_yara_rule", "analyze_pcap", "checksec", "decompile",
        "decompile_function", "disassemble", "disassemble_binary",
        "extract_strings", "file_info", "search_gadgets", "cyclic_pattern",
        "cast_keccak", "aes_encrypt", "aes_decrypt",
        "decode_hex", "encode_base64", "decode_base64", "hash_data",
        "extract_iocs", "compute_threat_score",
    }
    if job.tool not in offline and job.tool not in NETWORK_CONTAINER_TOOLS:
        raise HTTPException(503, "This capability requires a verified egress or lab network profile")
    if job.tool in NETWORK_CONTAINER_TOOLS and job.network_profile == "offline":
        raise HTTPException(400, "This capability requires an explicit network profile")
    if job.tool not in NETWORK_CONTAINER_TOOLS and job.network_profile != "offline":
        raise HTTPException(400, "Network access is not available to this executor")

    allowed_env: set[str] = set()
    if set(job.environment) - allowed_env or any(
        len(v) > 4096 or "\x00" in v for v in job.environment.values()
    ):
        raise HTTPException(400, "Environment is not permitted for this capability")

    _network_policy(job)
    host_root = _host_sessions_root()
    session_root = Path(os.environ["SESSIONS_ROOT"]).resolve(strict=True)
    relative = workspace.relative_to(session_root)
    host_workspace = Path(host_root) / relative

    options = dict(
        image=image,
        command=job.argv,
        entrypoint=[],
        user="10001:10001",
        working_dir=str(workspace),
        read_only=True,
        network_mode="none",
        runtime=os.environ.get("SANDBOX_RUNNER_RUNTIME", "runc"),
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        volumes={str(host_workspace): {"bind": str(workspace), "mode": "ro" if job.tool in READ_ONLY_TOOLS else "rw"}},
        environment={
            "PATH": "/opt/blackonyx/bin:/usr/local/bin:/usr/bin:/bin",
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "TERM": "dumb",
            **job.environment,
        },
        tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=67108864,mode=1777"},
        mem_limit="1g",
        nano_cpus=1000000000,
        pids_limit=50,
        labels={"black-onyx.runner": "tool"},
        detach=True,
        stdin_open=False,
        init=True,
        log_config={"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}},
    )
    return options


def _attach_guard_network(options: dict, guard_id: str, pinned: dict[str, list[str]]) -> dict:
    """Join the guard netns and pin preview hostnames in the executor /etc/hosts."""
    attached = dict(options)
    attached["network_mode"] = f"container:{guard_id}"
    pinned_hosts = extra_hosts(pinned)
    if pinned_hosts:
        attached["extra_hosts"] = pinned_hosts
    return attached


def _rewrite_run_binary_path(job: Execution, workspace: Path) -> None:
    """Run a workspace file as ./name so timeout does not search PATH for it."""
    if job.tool != "run_binary" or len(job.argv) < 3:
        return
    target = job.argv[2]
    if not isinstance(target, str) or "/" in target or target in {".", ".."} or "\x00" in target:
        return
    try:
        root = workspace.resolve(strict=True)
        candidate = (workspace / target).resolve()
    except OSError:
        return
    if candidate.parent != root or not candidate.is_file() or candidate.is_symlink():
        return
    rewritten = list(job.argv)
    rewritten[2] = f"./{target}"
    job.argv = rewritten


def _host_guard_policy_root() -> tuple[Path, Path]:
    """Return private policy paths under the runner's existing workspace bind."""
    runner_root = Path(os.environ["SESSIONS_ROOT"]).resolve(strict=True)
    runner_path = runner_root / ".guard-policies"
    if runner_path.is_symlink():
        raise HTTPException(503, "Guard policy directory cannot be a symlink")
    runner_path.mkdir(mode=0o700, exist_ok=True)
    if runner_path.resolve().parent != runner_root or not os.access(runner_path, os.W_OK):
        raise HTTPException(503, "Guard policy directory is unavailable")
    daemon_path = Path(_host_sessions_root()) / ".guard-policies"
    if not daemon_path.is_absolute():
        raise HTTPException(503, "Guard policy mount source is invalid")
    return runner_path, daemon_path


def _local_image(client, image_ref: str):
    """Load a digest-pinned image from a registry ref or a local image id."""
    expected_digest = image_ref.rsplit("@", 1)[1]
    image = None
    last_exc: Exception | None = None
    for candidate in (image_ref, expected_digest):
        try:
            image = client.images.get(candidate)
            break
        except Exception as exc:
            last_exc = exc
    if image is None:
        raise HTTPException(503, "Digest-pinned executor image is not present locally") from last_exc
    repo_digests = (image.attrs or {}).get("RepoDigests") or []
    image_id = str((image.attrs or {}).get("Id") or "")
    if image_id != expected_digest and not any(
        item.rsplit("@", 1)[-1] == expected_digest for item in repo_digests
    ):
        raise HTTPException(503, "Local executor image digest does not match configured digest")
    return image


def _resolved_image_id(client, image_ref: str) -> str:
    return str(_local_image(client, image_ref).id)


def _assert_local_digest_image(client, image_ref: str) -> None:
    """Reject missing images and local tags that do not carry the configured digest."""
    _local_image(client, image_ref)


def _assert_network_registration(client, network_name: str, *, profile_id: str | None) -> None:
    try:
        network = client.networks.get(network_name)
        attrs = network.attrs or {}
    except Exception as exc:
        raise HTTPException(503, "Registered executor network is unavailable") from exc
    labels = attrs.get("Labels") or {}
    if profile_id is None:
        valid = labels.get("com.blackonyx.security-egress") == "true" and not attrs.get("Internal", False)
    else:
        valid = (
            labels.get("com.blackonyx.security-lab-profile") == profile_id
            and bool(attrs.get("Internal", False))
        )
    if not valid or attrs.get("EnableIPv6", False):
        raise HTTPException(503, "Executor network does not match its registered isolation profile")


def _create_egress_guard(client, job: Execution, job_id: str):
    """Start a trusted firewall namespace before attaching the untrusted toolbox."""
    from security_runner.egress_policy import (
        EgressDenied, nftables_policy_script, validate_resolved_targets,
    )

    network_name, lab = _network_policy(job)
    profile_id = job.lab_profile_id if job.network_profile == "lab" else None
    _validate_guard_image()
    guard_image = os.environ["SECURITY_GUARD_IMAGE"]
    _assert_local_digest_image(client, guard_image)
    _assert_network_registration(client, network_name, profile_id=profile_id)
    network_attrs = client.networks.get(network_name).attrs or {}
    blocked_ips = []
    for item in ((network_attrs.get("IPAM") or {}).get("Config") or []):
        gateway = item.get("Gateway")
        if isinstance(gateway, str):
            blocked_ips.append(gateway)

    if lab is None:
        lab_cidrs = ()
    else:
        lab_cidrs = lab["cidrs"]
    try:
        if not job.resolved_targets:
            raise EgressDenied("Target addresses must be resolved during preview")
        pinned, addresses = validate_resolved_targets(
            job.destinations, job.resolved_targets,
            profile=job.network_profile, lab_cidrs=lab_cidrs,
            blocked_ips=blocked_ips,
        )
        firewall = nftables_policy_script(addresses, job.ports)
    except EgressDenied as exc:
        raise HTTPException(403, "Requested destination failed network policy validation") from exc

    runner_root, daemon_root = _host_guard_policy_root()
    policy_id = re.sub(r"[^A-Za-z0-9_-]", "", job_id)
    policy_dir = runner_root / policy_id
    host_policy_dir = daemon_root / policy_id
    policy_dir.mkdir(mode=0o755, parents=False, exist_ok=False)
    if policy_dir.is_symlink() or policy_dir.resolve().parent != runner_root.resolve():
        policy_dir.rmdir()
        raise HTTPException(503, "Guard policy path escaped its mounted directory")
    policy_file = policy_dir / "nftables.conf"
    fd = os.open(policy_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(fd, "w", encoding="ascii") as output:
        output.write(firewall)
    os.chmod(policy_file, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    guard = None
    try:
        create_options = {
            "image": _resolved_image_id(client, guard_image),
            "command": ["/bin/sleep", "infinity"],
            "entrypoint": [],
            "user": "0:0",
            "network": network_name,
            "read_only": True,
            "cap_drop": ["ALL"],
            "cap_add": ["NET_ADMIN"],
            "security_opt": ["no-new-privileges:true"],
            "volumes": {str(host_policy_dir): {"bind": "/policy", "mode": "ro"}},
            "tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"},
            "mem_limit": "64m",
            "nano_cpus": 100000000,
            "pids_limit": 8,
            "labels": {
                "black-onyx.runner": "guard",
                "black-onyx.runner-id": os.environ.get("HOSTNAME", "runner"),
                "black-onyx.job": job_id,
                "black-onyx.profile": job.network_profile,
            },
            "detach": True,
            "init": True,
            "log_config": {"Type": "local", "Config": {"max-size": "64k", "max-file": "1", "compress": "false"}},
        }
        guard = client.containers.create(**create_options)
        with _jobs_lock:
            current = _jobs.get(job_id)
            if current is None or current["cancelled"]:
                raise RuntimeError("job cancelled before guard start")
            current["guard"] = guard
            current["policy_dir"] = str(policy_dir)
        guard.start()
        result = guard.exec_run(["nft", "-f", "/policy/nftables.conf"], demux=True)
        exit_code = result.exit_code if hasattr(result, "exit_code") else result[0]
        if exit_code != 0:
            output = result.output if hasattr(result, "output") else result[1]
            detail = output[1] if isinstance(output, tuple) and len(output) > 1 else output
            message = detail.decode("utf-8", errors="replace") if isinstance(detail, bytes) else str(detail)
            raise RuntimeError(f"firewall policy could not be installed: {message.strip()[:240]}")
        return guard, pinned
    except Exception:
        if guard is not None:
            try:
                guard.remove(force=True)
            except Exception:
                logger.exception("Could not remove failed egress guard for job %s", job_id)
        shutil.rmtree(policy_dir, ignore_errors=True)
        raise


class ResolveTargetsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    network_profile: Literal["public", "lab"]
    destinations: list[str] = Field(min_length=1, max_length=100)
    ports: list[int] = Field(min_length=1, max_length=64)
    lab_profile_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")


class CaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    session: str = Field(pattern=r"^[a-f0-9]{64}/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    lab_profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    duration: int = Field(ge=1, le=30)
    filter: str = Field(default="", max_length=256)
    job_id: str = Field(pattern=r"^[A-Za-z0-9_-]{8,64}$")


def _capture_filter(value: str) -> str:
    if value and (
        not re.fullmatch(r"[A-Za-z0-9().:/_= -]{1,256}", value)
        or not value[0].isalnum() and value[0] != "("
        or "  " in value
    ):
        raise HTTPException(400, "Capture filter contains unsupported syntax")
    return value


def _configured_lab_profile(profile_id: str) -> dict[str, object]:
    from security_runner.egress_policy import EgressDenied, parse_lab_profiles

    if (
        os.environ.get("SECURITY_EGRESS_VERIFIED", "").lower() != "true"
        or os.environ.get("SECURITY_CAPTURE_VERIFIED", "").lower() != "true"
        or os.environ.get("ALLOW_PRIVATE_TARGETS", "").lower() != "true"
    ):
        raise HTTPException(503, "Independent lab capture verification is not enabled")
    try:
        profile = parse_lab_profiles(_read_secret("SECURITY_LAB_PROFILES_JSON")).get(profile_id)
    except EgressDenied as exc:
        raise HTTPException(503, "Registered lab configuration is invalid") from exc
    if profile is None:
        raise HTTPException(403, "Unknown lab profile")
    _validate_guard_image()
    return profile


@app.post("/resolve-targets")
def resolve_targets(body: ResolveTargetsRequest, authorization: str | None = Header(None)) -> dict[str, object]:
    """Resolve a preview scope once; execution uses these exact pinned addresses."""
    authorize(authorization)
    from security_runner.egress_policy import (
        EgressDenied, nftables_policy_script, resolve_ipv4_targets,
    )

    job = Execution(
        session="0" * 64 + "/preview", tool="nmap_scan", argv=["nmap", "--version"],
        timeout=30, network_profile=body.network_profile, destinations=body.destinations,
        ports=body.ports, lab_profile_id=body.lab_profile_id,
    )
    network_name, lab = _network_policy(job)
    try:
        guard_image = _validate_guard_image()
        import docker

        client = docker.from_env(timeout=10)
        try:
            _assert_local_digest_image(client, guard_image)
            _assert_network_registration(
                client, network_name,
                profile_id=body.lab_profile_id if body.network_profile == "lab" else None,
            )
            network_attrs = client.networks.get(network_name).attrs or {}
        finally:
            client.close()
        blocked_ips = [
            item["Gateway"] for item in ((network_attrs.get("IPAM") or {}).get("Config") or [])
            if isinstance(item.get("Gateway"), str)
        ]
        lab_cidrs = lab["cidrs"] if lab is not None else ()
        pinned, addresses = resolve_ipv4_targets(
            body.destinations, profile=body.network_profile, lab_cidrs=lab_cidrs,
            blocked_ips=blocked_ips,
        )
        nftables_policy_script(addresses, body.ports)
    except EgressDenied as exc:
        raise HTTPException(403, "Network target preview failed policy validation") from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Network target preview unavailable: %s", type(exc).__name__)
        raise HTTPException(503, "Network target preview is unavailable") from exc
    return {"resolved_targets": pinned}


@app.get("/capture-ready")
def capture_ready(authorization: str | None = Header(None)) -> dict[str, object]:
    authorize(authorization)
    if (
        os.environ.get("SECURITY_EGRESS_VERIFIED", "").lower() != "true"
        or os.environ.get("SECURITY_CAPTURE_VERIFIED", "").lower() != "true"
        or os.environ.get("ALLOW_PRIVATE_TARGETS", "").lower() != "true"
    ):
        return {"ready": False}
    try:
        from security_runner.egress_policy import parse_lab_profiles
        profiles = parse_lab_profiles(_read_secret("SECURITY_LAB_PROFILES_JSON"))
        if not profiles:
            return {"ready": False}
        _validate_guard_image()
        import docker
        client = docker.from_env(timeout=10)
        try:
            _assert_local_digest_image(client, os.environ["SECURITY_GUARD_IMAGE"])
            for profile_id, profile in profiles.items():
                _assert_network_registration(client, str(profile["network"]), profile_id=profile_id)
        finally:
            client.close()
    except Exception as exc:
        logger.warning("Registered lab capture readiness failed: %s", type(exc).__name__)
        return {"ready": False}
    return {"ready": True, "profiles": sorted(profiles)}


@app.post("/capture")
def capture_packets(body: CaptureRequest, authorization: str | None = Header(None)) -> dict[str, object]:
    """Capture bounded PCAP bytes inside a trusted, isolated lab namespace."""
    authorize(authorization)
    _capture_filter(body.filter)
    capture_job = Execution(
        session=body.session, tool="Read", argv=["true"], timeout=body.duration,
        job_id=body.job_id,
    )
    job_id = _register_job(capture_job)
    policy_dir: Path | None = None
    guard = None
    client = None
    try:
        profile = _configured_lab_profile(body.lab_profile_id)
        import docker
        from security_runner.egress_policy import nftables_deny_all_script

        client = docker.from_env(timeout=body.duration + 15)
        _assert_local_digest_image(client, os.environ["SECURITY_GUARD_IMAGE"])
        _assert_network_registration(client, str(profile["network"]), profile_id=body.lab_profile_id)
        runner_root, daemon_root = _host_guard_policy_root()
        policy_dir = runner_root / job_id
        host_policy_dir = daemon_root / job_id
        policy_dir.mkdir(mode=0o755, parents=False, exist_ok=False)
        policy_file = policy_dir / "nftables.conf"
        fd = os.open(policy_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(fd, "w", encoding="ascii") as output:
            output.write(nftables_deny_all_script())
        os.chmod(policy_file, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        guard = client.containers.create(
            image=_resolved_image_id(client, os.environ["SECURITY_GUARD_IMAGE"]),
            command=["/bin/sleep", "infinity"], entrypoint=[], user="0:0",
            network=str(profile["network"]), read_only=True,
            cap_drop=["ALL"], cap_add=["NET_ADMIN", "NET_RAW"],
            security_opt=["no-new-privileges:true"],
            volumes={str(host_policy_dir): {"bind": "/policy", "mode": "ro"}},
            tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"},
            mem_limit="96m", nano_cpus=200000000, pids_limit=8,
            labels={
                "black-onyx.runner": "guard",
                "black-onyx.runner-id": os.environ.get("HOSTNAME", "runner"),
                "black-onyx.job": job_id,
                "black-onyx.profile": "capture",
            },
            detach=True, init=True,
            log_config={"Type": "local", "Config": {"max-size": "64k", "max-file": "1", "compress": "false"}},
        )
        with _jobs_lock:
            current = _jobs.get(job_id)
            if current is None or current["cancelled"]:
                raise RuntimeError("capture cancelled before start")
            current["guard"] = guard
            current["policy_dir"] = str(policy_dir)
        guard.start()
        firewall = guard.exec_run(["nft", "-f", "/policy/nftables.conf"], demux=True)
        firewall_code = firewall.exit_code if hasattr(firewall, "exit_code") else firewall[0]
        if firewall_code != 0:
            raise RuntimeError("capture namespace firewall could not be installed")
        command = [
            "timeout", f"{body.duration}s", "tcpdump", "-n", "-i", "any",
            "-s", "256", "-U", "-c", "4096", "-w", "-",
        ]
        if body.filter:
            command.append(body.filter)
        result = guard.exec_run(command, demux=True, user="0:0")
        exit_code, output = result if isinstance(result, tuple) else (result.exit_code, result.output)
        stdout = output[0] if isinstance(output, tuple) else output
        pcap = stdout or b""
        if len(pcap) > 1_200_000 or len(pcap) < 24 or pcap[:4] not in {
            b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
            b"\x0a\x0d\x0d\x0a",
        }:
            raise RuntimeError("Capture returned an invalid or oversized PCAP")
        cancelled = bool(_jobs.get(job_id, {}).get("cancelled"))
        if cancelled:
            return {"status": "cancelled", "job_id": job_id}
        return {
            "status": "success", "job_id": job_id, "format": "pcap",
            "duration_s": body.duration, "captured_bytes": len(pcap),
            "sha256": hashlib.sha256(pcap).hexdigest(),
            "content_base64": base64.b64encode(pcap).decode("ascii"),
            "returncode": int(exit_code),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Trusted packet capture failed: %s: %s", type(exc).__name__, str(exc)[:240])
        raise HTTPException(503, "Trusted packet capture is unavailable") from exc
    finally:
        if guard is not None:
            try:
                guard.remove(force=True)
            except Exception:
                logger.warning("Failed to remove capture guard for job %s", job_id)
        if client is not None:
            client.close()
        if policy_dir is not None:
            shutil.rmtree(policy_dir, ignore_errors=True)
        _release_job(job_id)


@app.get("/network-ready")
async def network_ready(authorization: str | None = Header(None)) -> dict[str, object]:
    """Report verified local guard prerequisites without pulling or building images."""
    authorize(authorization)
    if os.environ.get("SECURITY_EGRESS_VERIFIED", "").lower() != "true":
        return {"ready": False, "reason": "independent executor verification is not recorded"}
    try:
        guard_image = _validate_guard_image()
        public_network = os.environ.get("SECURITY_EGRESS_NETWORK", "")
        if not public_network:
            return {"ready": False, "reason": "public egress network is not configured"}
        import docker

        client = docker.from_env(timeout=10)
        try:
            _assert_local_digest_image(client, guard_image)
            _assert_network_registration(client, public_network, profile_id=None)
        finally:
            client.close()
    except Exception as exc:
        logger.warning("Per-job egress readiness failed: %s", type(exc).__name__)
        return {"ready": False, "reason": "guard image or public network validation failed"}
    return {"ready": True, "guard_image": guard_image, "public_network": public_network}


@app.on_event("startup")
def clean_orphaned_egress_guards() -> None:
    """Remove guards left by a crashed instance before accepting new jobs."""
    runner_id = os.environ.get("HOSTNAME", "")
    if not runner_id:
        return
    try:
        import docker

        client = docker.from_env(timeout=10)
        try:
            orphaned = client.containers.list(
                all=True, filters={"label": f"black-onyx.runner-id={runner_id}"},
            )
            policy_root = Path(os.environ["SESSIONS_ROOT"]) / ".guard-policies"
            for container in orphaned:
                labels = container.labels or {}
                if labels.get("black-onyx.runner") not in {"guard", "tool"}:
                    continue
                job_id = labels.get("black-onyx.job", "")
                try:
                    container.remove(force=True)
                except Exception:
                    logger.exception("Failed to remove orphan executor container")
                if re.fullmatch(r"[A-Za-z0-9_-]{8,64}", job_id):
                    candidate = policy_root / job_id
                    if candidate.parent.resolve() == policy_root.resolve() and not candidate.is_symlink():
                        shutil.rmtree(candidate, ignore_errors=True)
        finally:
            client.close()
    except Exception as exc:
        # Offline jobs remain safe. Network jobs independently fail closed if
        # the Docker daemon, guard image, or registered network is unavailable.
        logger.warning("Orphan guard cleanup unavailable: %s", type(exc).__name__)


def _host_sessions_root() -> Path | PureWindowsPath:
    """Get the mount source as resolved by the Docker daemon, not the host shell.

    Docker Desktop translates Windows bind paths to a Linux daemon path. Using
    the caller's Windows string as a new bind source would mount a different
    location, so inspect this container's existing /workspace mount instead.
    """
    import docker

    container_id = os.environ.get("HOSTNAME", "")
    if not container_id:
        raise HTTPException(503, "Runner container identity is unavailable")
    try:
        client = docker.from_env(timeout=10)
        try:
            mounts = client.containers.get(container_id).attrs.get("Mounts", [])
        finally:
            client.close()
    except Exception as exc:
        raise HTTPException(503, "Runner workspace mount could not be inspected") from exc
    matches = [mount for mount in mounts if mount.get("Destination") == "/workspace"]
    if len(matches) != 1 or matches[0].get("Type") != "bind":
        raise HTTPException(503, "Runner requires one bind-mounted workspace root")
    source = matches[0].get("Source", "")
    if not isinstance(source, str):
        raise HTTPException(503, "Runner workspace mount source is invalid")
    host_path: Path | PureWindowsPath = (
        PureWindowsPath(source) if re.match(r"^[A-Za-z]:\\", source) else Path(source)
    )
    if not host_path.is_absolute():
        raise HTTPException(503, "Runner workspace mount source is invalid")
    return host_path


@app.get("/healthz")
async def liveness() -> dict[str, str]:
    """Cheap liveness probe no Docker/DB round-trips."""
    return {"status": "alive"}


@app.post("/execute")
async def execute(
    job: Execution,
    authorization: str | None = Header(None),
) -> dict:
    """Execute a command in an ephemeral container for the given session."""
    authorize(authorization)
    image = _validate_image()
    workspace = _resolve_workspace(job.session)
    _rewrite_run_binary_path(job, workspace)
    options = _container_options(job, image, workspace)
    _check_quota(workspace)
    job_id = _register_job(job)
    options["labels"].update({
        "black-onyx.runner-id": os.environ.get("HOSTNAME", "runner"),
        "black-onyx.job": job_id,
    })
    try:
        async with slots:
            result = await asyncio.to_thread(_run_container, job, options, job_id)
    finally:
        _release_job(job_id)
    result["job_id"] = job_id
    return result


# Probe run inside the sandbox image: reports which executables ("bin:") and
# Python modules ("py:") exist. Arguments are data, never shell input.
PROBE_SCRIPT = (
    "import importlib.util,json,os,shutil,sys\n"
    "out={}\n"
    "for item in sys.argv[1:]:\n"
    "    kind,name=item.split(':',1)\n"
    "    if kind=='bin': out[item]=bool(shutil.which(name))\n"
    "    elif kind=='py': out[item]=importlib.util.find_spec(name) is not None\n"
    "    else:\n"
    "        from pathlib import Path\n"
    "        helper=Path('/usr/share/blackonyx')/name\n"
    "        out[item]=helper.parent==Path('/usr/share/blackonyx') and helper.is_file() and not helper.is_symlink() and not os.access(helper,os.W_OK)\n"
    "print(json.dumps(out))\n"
)
_capability_cache: dict[tuple[str, tuple[str, ...]], dict[str, bool]] = {}


class ProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    requirements: list[str] = Field(min_length=1, max_length=100)

    def validated(self) -> tuple[str, ...]:
        for item in self.requirements:
            if not re.fullmatch(r"(?:bin|py):[A-Za-z0-9_.+-]{1,64}|helper:[A-Za-z0-9_.+-]{1,64}", item):
                raise HTTPException(400, f"Invalid requirement: {item[:80]}")
        return tuple(sorted(set(self.requirements)))


def _probe_options(image: str, requirements: tuple[str, ...]) -> dict:
    return dict(
        image=image,
        command=["python3", "-c", PROBE_SCRIPT, *requirements],
        entrypoint=[],
        user="10001:10001",
        working_dir="/tmp",
        read_only=True,
        network_mode="none",
        runtime=os.environ.get("SANDBOX_RUNNER_RUNTIME", "runc"),
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        environment={"PATH": "/opt/blackonyx/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "TERM": "dumb"},
        tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"},
        mem_limit="256m",
        nano_cpus=500000000,
        pids_limit=20,
        labels={"black-onyx.runner": "true"},
        detach=True,
        init=True,
    )


def _run_probe(options: dict) -> dict[str, bool]:
    import docker

    client = docker.from_env(timeout=45)
    container = None
    try:
        options = dict(options)
        options["image"] = _resolved_image_id(client, options["image"])
        container = client.containers.create(**options)
        container.start()
        result = container.wait(timeout=30)
        output = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace").strip()
        if result.get("StatusCode", 1) != 0 or not output:
            raise RuntimeError("probe failed")
        parsed = json.loads(output.splitlines()[-1])
        return {str(key): bool(value) for key, value in parsed.items()}
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                logger.warning("Failed to remove capability probe container")
        client.close()


@app.post("/capabilities")
async def probe_capabilities(body: ProbeRequest, authorization: str | None = Header(None)) -> dict:
    """Attest which tool requirements the digest-pinned sandbox image provides."""
    authorize(authorization)
    image = _validate_image()
    requirements = body.validated()
    key = (image, requirements)
    if key not in _capability_cache:
        try:
            _capability_cache[key] = await asyncio.to_thread(_run_probe, _probe_options(image, requirements))
        except Exception as exc:
            raise HTTPException(503, f"Capability probe failed: {type(exc).__name__}") from exc
    return {"image": image, "requirements": _capability_cache[key]}


@app.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, body: CancelRequest, authorization: str | None = Header(None)) -> dict:
    """Stop a running job; only the owning session may cancel it."""
    authorize(authorization)
    with _jobs_lock:
        entry = _jobs.get(job_id)
        if entry is None or entry["session"] != body.session:
            raise HTTPException(404, "Unknown job")
        entry["cancelled"] = True
        container = entry["container"]
        guard = entry["guard"]
    for active_container in (container, guard):
        if active_container is None:
            continue
        try:
            active_container.kill()
        except Exception:
            logger.warning("Failed to kill job container for job %s", job_id)
    return {"status": "cancelling", "job_id": job_id}


def _run_container(job: Execution, options: dict, job_id: str | None = None) -> dict:
    """Keep blocking Docker API calls off the FastAPI event loop."""
    import docker
    import time as _time

    started = _time.monotonic()
    client = None
    input_path: Path | None = None
    container = None
    guard = None
    policy_dir: str | None = None
    try:
        if job.stdin:
            # Docker's attach_socket half-close is unreliable across Docker
            # Desktop's HTTP bridge. Stage input in the owned workspace and
            # redirect fd 0 in a Python exec wrapper, never through a shell or
            # the Docker command line.
            input_path = Path(options["working_dir"]) / f".stdin-{secrets.token_hex(16)}"
            fd = os.open(input_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as source:
                source.write(job.stdin.encode())
            options = dict(options)
            options["command"] = [
                "python3", "-c",
                "import os,sys;f=open(sys.argv[1],'rb');os.dup2(f.fileno(),0);os.execvp(sys.argv[2],sys.argv[2:])",
                str(input_path), *job.argv,
            ]
        client = docker.from_env(timeout=job.timeout + 15)
        options = dict(options)
        options["image"] = _resolved_image_id(client, options["image"])
        if job.network_profile != "offline":
            guard, pinned = _create_egress_guard(client, job, job_id or secrets.token_hex(12))
            options = _attach_guard_network(options, guard.id, pinned)
            with _jobs_lock:
                current = _jobs.get(job_id or "")
                if current is not None:
                    current["guard"] = guard
                    policy_dir = current["policy_dir"]
        container = client.containers.create(**options)
        if job_id is not None:
            with _jobs_lock:
                entry = _jobs.get(job_id)
                if entry is not None:
                    entry["container"] = container
                    if entry["cancelled"]:
                        raise RuntimeError("cancelled before start")
        container.start()
        result = container.wait(timeout=job.timeout)
        logs = container.logs(stdout=True, stderr=True, timestamps=False).decode(
            "utf-8", errors="replace"
        )
        returncode = result.get("StatusCode", 1)
        cancelled = bool(job_id and _jobs.get(job_id, {}).get("cancelled"))
        if cancelled:
            return {
                "status": "cancelled", "output": logs[:50000], "returncode": returncode,
                "duration_s": round(_time.monotonic() - started, 3),
                "timed_out": False, "cancelled": True,
            }
        return {
            "status": "success" if returncode == 0 else "error",
            "output": logs[:50000], "returncode": returncode,
            "duration_s": round(_time.monotonic() - started, 3),
            "timed_out": False,
        }
    except Exception as exc:
        if job_id and _jobs.get(job_id, {}).get("cancelled"):
            return {
                "status": "cancelled", "output": "", "returncode": 137,
                "duration_s": round(_time.monotonic() - started, 3),
                "timed_out": False, "cancelled": True,
            }
        timed_out = type(exc).__name__ in {"ReadTimeout", "Timeout", "TimeoutError"}
        return {
            "status": "error", "output": "", "returncode": 124 if timed_out else 1,
            "duration_s": round(_time.monotonic() - started, 3),
            "timed_out": timed_out,
            "error": "Execution timed out" if timed_out else f"Execution failed: {type(exc).__name__}: {exc}"[:400],
        }
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                logger.warning("Failed to remove container for session %s", job.session)
        if guard is not None:
            try:
                guard.remove(force=True)
            except Exception:
                logger.warning("Failed to remove egress guard for session %s", job.session)
        if client is not None:
            client.close()
        if input_path is not None:
            input_path.unlink(missing_ok=True)
        if policy_dir is not None:
            shutil.rmtree(policy_dir, ignore_errors=True)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("SECURITY_RUNNER_PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
