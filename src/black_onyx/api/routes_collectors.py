"""Downloadable host collector packages (osquery + shipper) per OS."""

from __future__ import annotations

import io
import os
import shlex
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from black_onyx.auth.context import get_auth_service
from black_onyx.auth.dependencies import current_principal
from black_onyx.auth.service import Principal, Role

collectors_router = APIRouter(tags=["collectors"])

_SUPPORTED = ("linux", "windows", "macos")

_PACKAGE_FILES: dict[str, tuple[tuple[str, str], ...]] = {
    "linux": (
        ("install.sh", "installer/linux/install.sh"),
        ("install-via-docker.sh", "installer/linux/install-via-docker.sh"),
        ("install-in-container.sh", "installer/linux/install-in-container.sh"),
        ("README.txt", "installer/linux/README.txt"),
        ("osquery/packs/incident_response.conf", "osquery/packs/incident_response.conf"),
        ("osquery/config/linux.conf", "osquery/config/linux.conf"),
        ("shipper/black_onyx_shipper.py", "shipper/black_onyx_shipper.py"),
        ("shipper/install.sh", "shipper/install.sh"),
        ("shipper/black-onyx-shipper.service", "shipper/black-onyx-shipper.service"),
        ("shipper/shipper.env.example", "shipper/shipper.env.example"),
        ("vector/profiles/host_state_http.toml", "vector/profiles/host_state_http.toml"),
    ),
    "windows": (
        ("install.ps1", "installer/windows/install.ps1"),
        ("README.txt", "installer/windows/README.txt"),
        ("osquery/packs/incident_response.conf", "osquery/packs/incident_response.conf"),
        ("osquery/config/windows.conf", "osquery/config/windows.conf"),
        ("shipper/black_onyx_shipper.py", "shipper/black_onyx_shipper.py"),
        ("shipper/shipper.env.example", "shipper/shipper.env.example"),
        ("vector/profiles/host_state_http.toml", "vector/profiles/host_state_http.toml"),
    ),
    "macos": (
        ("install.sh", "installer/macos/install.sh"),
        ("README.txt", "installer/macos/README.txt"),
        ("osquery/packs/incident_response.conf", "osquery/packs/incident_response.conf"),
        ("osquery/config/darwin.conf", "osquery/config/darwin.conf"),
        ("shipper/black_onyx_shipper.py", "shipper/black_onyx_shipper.py"),
        ("shipper/shipper.env.example", "shipper/shipper.env.example"),
        ("vector/profiles/host_state_http.toml", "vector/profiles/host_state_http.toml"),
    ),
}


def _remote_service_url(prefix: str, *, host_port: int, remote_port: int) -> str:
    """Public URL for collectors; prefers INGEST_GATEWAY_REMOTE_* / ASSET_REGISTRY_REMOTE_*."""
    for key in (f"{prefix}_URL", f"{prefix}_REMOTE_URL"):
        explicit = (os.environ.get(key) or "").strip()
        if explicit:
            return explicit.rstrip("/")
    remote_bind = (os.environ.get(f"{prefix}_REMOTE_BIND") or "").strip()
    if remote_bind and remote_bind not in ("127.0.0.1", "0.0.0.0"):
        port = (os.environ.get(f"{prefix}_REMOTE_PORT") or "").strip() or str(remote_port)
        tls = (os.environ.get(f"{prefix}_REMOTE_TLS") or "").lower() in ("1", "true", "yes")
        scheme = "https" if tls else "http"
        return f"{scheme}://{remote_bind}:{port}".rstrip("/")
    host = (os.environ.get(f"{prefix}_REMOTE_HOST") or "").strip() or "127.0.0.1"
    port = (os.environ.get(f"{prefix}_HOST_PORT") or "").strip() or str(host_port)
    return f"http://{host}:{port}".rstrip("/")


_LOOPBACK_HOSTS = {"", "127.0.0.1", "0.0.0.0", "localhost", "::1"}

# Shown to non-admins (and for unset secrets) instead of the credential itself.
REDACTED = "********"

# Enrollment secrets an administrator may reveal: response field -> env vars.
_SECRET_SOURCES: dict[str, tuple[str, ...]] = {
    "ingest_key": ("BLACK_ONYX_COLLECTOR_INGEST_KEY", "API_KEYS"),
    "registry_service_key": ("ASSET_REGISTRY_SERVICE_KEY",),
    "wazuh_registration_password": ("WAZUH_REGISTRATION_PASSWORD",),
}


def _secret_value(field: str) -> str:
    for env_name in _SECRET_SOURCES[field]:
        raw = (os.environ.get(env_name) or "").strip()
        if raw:
            # API_KEYS is a CSV; collectors use the first key.
            return raw.split(",")[0].strip()
    return ""


def _wazuh_manager_address(request_host: str | None = None) -> tuple[str, bool]:
    """Address agents use to reach the host Wazuh manager (1514/1515 tcp).

    Order: WAZUH_MANAGER_ADDRESS, the remote collector bind (the host's
    Tailscale/LAN address), the platform external hostname, then the host the
    operator used to reach this UI. Returns (address, reachable_off_host).
    """
    explicit = (os.environ.get("WAZUH_MANAGER_ADDRESS") or "").strip()
    if explicit:
        return explicit, True
    for key in ("INGEST_GATEWAY_REMOTE_BIND", "ASSET_REGISTRY_REMOTE_BIND"):
        bind = (os.environ.get(key) or "").strip()
        if bind not in _LOOPBACK_HOSTS:
            return bind, True
    external = urlsplit((os.environ.get("QDRANT_SECURITY__EXTERNAL_URL") or "").strip()).hostname or ""
    if external not in _LOOPBACK_HOSTS:
        return external, True
    host = (request_host or "").strip() or "127.0.0.1"
    return host, host not in _LOOPBACK_HOSTS


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _wazuh_agent_commands(manager: str, registration_password: str) -> dict[str, str]:
    """Stock agent installs from the signed Wazuh 4.x repositories."""
    env = (
        f"WAZUH_MANAGER={shlex.quote(manager)} "
        f"WAZUH_REGISTRATION_PASSWORD={shlex.quote(registration_password)}"
    )
    return {
        "agent_linux_deb": " && ".join([
            "curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg",
            "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' "
            "| sudo tee /etc/apt/sources.list.d/wazuh.list",
            "sudo apt-get update",
            f"sudo {env} apt-get install -y wazuh-agent",
            "sudo systemctl daemon-reload",
            "sudo systemctl enable --now wazuh-agent",
        ]),
        "agent_linux_rpm": " && ".join([
            "sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH",
            "printf '[wazuh]\\ngpgcheck=1\\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\\nenabled=1\\n"
            "name=Wazuh\\nbaseurl=https://packages.wazuh.com/4.x/yum/\\nprotect=1\\n' "
            "| sudo tee /etc/yum.repos.d/wazuh.repo",
            f"sudo {env} dnf install -y wazuh-agent",
            "sudo systemctl daemon-reload",
            "sudo systemctl enable --now wazuh-agent",
        ]),
        "agent_windows": (
            "# Elevated PowerShell; download the MSI matching the manager version from "
            "https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html\n"
            f"msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER={_ps_quote(manager)} "
            f"WAZUH_REGISTRATION_PASSWORD={_ps_quote(registration_password)}; NET START Wazuh"
        ),
    }


def _guide_context(*, reveal: bool, request_host: str | None = None) -> dict[str, Any]:
    tenant = (os.environ.get("BLACK_ONYX_DETECTION_TENANT") or "").strip()
    if not tenant:
        raise HTTPException(status_code=503, detail="BLACK_ONYX_DETECTION_TENANT is not configured")
    manager, manager_reachable = _wazuh_manager_address(request_host)
    secrets: dict[str, str] = {}
    missing: list[str] = []
    for field in _SECRET_SOURCES:
        value = _secret_value(field)
        if not value:
            missing.append(field)
        secrets[field] = value if (reveal and value) else REDACTED
    return {
        "gateway_url": _remote_service_url("INGEST_GATEWAY", host_port=18090, remote_port=18091),
        "registry_url": _remote_service_url("ASSET_REGISTRY", host_port=18081, remote_port=18082),
        "tenant_id": tenant,
        "wazuh_manager": manager,
        "wazuh_manager_reachable": manager_reachable,
        "secrets_revealed": reveal,
        "missing_secrets": missing,
        **secrets,
    }


def _osquery_install_commands(ctx: dict[str, Any]) -> dict[str, str]:
    g, t, k = ctx["gateway_url"], ctx["tenant_id"], ctx["ingest_key"]
    common = (
        f"BLACK_ONYX_COLLECTOR_TENANT_ID={shlex.quote(t)} "
        f"BLACK_ONYX_COLLECTOR_INGEST_KEY={shlex.quote(k)} "
        f"BLACK_ONYX_COLLECTOR_GATEWAY_URL={shlex.quote(g)}"
    )
    return {
        "linux": f"sudo {common} ./install.sh",
        "windows": f".\\install.ps1 -TenantId {_ps_quote(t)} -IngestKey {_ps_quote(k)} -GatewayUrl {_ps_quote(g)}",
        "macos": f"sudo {common} ./install.sh",
    }


def _structured_install_guides(ctx: dict[str, Any]) -> list[dict[str, object]]:
    g, r, t, k = ctx["gateway_url"], ctx["registry_url"], ctx["tenant_id"], ctx["ingest_key"]
    shipper_env = "\n".join([
        f"BLACK_ONYX_COLLECTOR_TENANT_ID={t}",
        f"BLACK_ONYX_COLLECTOR_GATEWAY_URL={g}",
        f"BLACK_ONYX_COLLECTOR_INGEST_KEY={k}",
        "BLACK_ONYX_COLLECTOR_ID=shipper-01",
        "SHIPPER_SOURCES=wazuh,suricata",
        "WAZUH_ALERTS_FILE=/var/ossec/logs/alerts/alerts.json",
        "SURICATA_EVE_FILE=/var/log/suricata/eve.json",
        f"ASSET_REGISTRY_URL={r}",
        f"ASSET_REGISTRY_SERVICE_KEY={ctx['registry_service_key']}",
    ])
    manager_note = (
        f"Agents enroll with the manager at {ctx['wazuh_manager']} (tcp 1514 events, 1515 enrollment)."
        if ctx["wazuh_manager_reachable"]
        else (
            f"{ctx['wazuh_manager']} is a loopback address; set WAZUH_MANAGER_ADDRESS (or a remote "
            "bind) so agents on other hosts can reach the manager."
        )
    )
    return [
        {
            "id": "osquery_shipper",
            "title": "Endpoint — osquery + shipper",
            "summary": "Download the OS package, unzip, and run the installer with tenant, ingest key, and gateway URL.",
            "components": ["osquery", "black-onyx-shipper (SHIPPER_SOURCES=osquery)"],
            "packages_os": list(_SUPPORTED),
            "commands": _osquery_install_commands(ctx),
            "notes": [
                "Loopback gateway default is http://127.0.0.1:18090; remote agents use the remote bind/port from compose.",
                "Optional: set ASSET_REGISTRY_URL in shipper.env for registry heartbeats.",
            ],
        },
        {
            "id": "wazuh",
            "title": "Wazuh manager / agents",
            "summary": "Install the shipper on the Wazuh manager (or use integrator push), enroll agents, then add a Wazuh connector in Detections.",
            "components": ["wazuh-manager integrator or shipper", "wazuh agents", "optional active-response isolation scripts"],
            "commands": {
                **_wazuh_agent_commands(ctx["wazuh_manager"], ctx["wazuh_registration_password"]),
                "manager_host_install": "sudo bash scripts/install_wazuh_host.sh",
                "manager_shipper": "SHIPPER_SOURCES=wazuh bash detection/collectors/wazuh/install-manager.sh",
                "manager_integrator": "WITH_INTEGRATOR=true SHIPPER_SOURCES=wazuh bash detection/collectors/wazuh/install-manager.sh",
                "agent_isolation_linux": "bash detection/collectors/wazuh/install-agent-ar.sh",
                "agent_isolation_windows": "powershell -ExecutionPolicy Bypass -File detection\\collectors\\wazuh\\install-agent-ar.ps1",
                "shipper_env": shipper_env,
            },
            "notes": [
                manager_note,
                "WAZUH_REGISTRATION_PASSWORD is generated by scripts/install_wazuh_host.sh into the platform .env.",
                "Issue a connector push token under Detections → Wazuh connector for SHIPPER_WAZUH_PUSH or integrator hook.",
                "Agent asset ids appear as wazuh:<agent-id> in the registry when heartbeats are enabled.",
            ],
        },
        {
            "id": "suricata",
            "title": "Suricata network sensor",
            "summary": "Install Suricata on a SPAN/TAP sensor, tail EVE JSON with the shipper, and set BLACK_ONYX_COLLECTOR_SENSOR_ID / BLACK_ONYX_COLLECTOR_ASSET_ID.",
            "components": ["suricata", "black-onyx-shipper (SHIPPER_SOURCES=suricata or wazuh,suricata)"],
            "commands": {
                "install": "SURICATA_INTERFACE=eth1 bash detection/collectors/suricata/install.sh",
                "shipper_env": shipper_env.replace("SHIPPER_SOURCES=wazuh,suricata", "SHIPPER_SOURCES=suricata"),
            },
            "notes": [
                "Suricata alerts ingest at /api/v1/ingest/suricata on the gateway URL above.",
                "Co-locate with Wazuh only when the shipper should read both alerts.json and eve.json.",
            ],
        },
    ]


def _collectors_root() -> Path:
    configured = (os.environ.get("BLACK_ONYX_COLLECTORS_DIR") or "").strip()
    if configured:
        path = Path(configured)
        if path.is_dir():
            return path
    here = Path(__file__).resolve()
    candidates = [
        here.parents[3] / "detection" / "collectors",
        Path("/app/detection/collectors"),
        Path.cwd() / "detection" / "collectors",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise HTTPException(status_code=503, detail="Collector packages are not available on this host")


def _require_ops(user: Principal = Depends(current_principal)) -> Principal:
    if user.role not in (Role.ADMIN, Role.ANALYST, Role.VIEWER):
        raise HTTPException(status_code=403, detail="Insufficient permission")
    return user


def _package_rows(root: Path, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    commands = _osquery_install_commands(ctx)
    rows = []
    for os_name in _SUPPORTED:
        missing = [src for _, src in _PACKAGE_FILES[os_name] if not (root / src).is_file()]
        rows.append({
            "os": os_name,
            "filename": f"black-onyx-collector-{os_name}.zip",
            "download_path": f"/api/v1/collectors/{os_name}/download",
            "available": not missing,
            "missing": missing,
            "install_command": commands[os_name],
            "components": ["osquery", "black-onyx-shipper (SHIPPER_SOURCES=osquery)"],
        })
    return rows


_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@collectors_router.get("/api/v1/collectors")
async def list_collectors(request: Request, _: Principal = Depends(_require_ops)) -> JSONResponse:
    root = _collectors_root()
    ctx = _guide_context(reveal=False, request_host=request.url.hostname)
    return JSONResponse({
        "packages": _package_rows(root, ctx),
        "root": str(root),
        "guide_path": "/api/v1/collectors/guide",
        "gateway_url": ctx["gateway_url"],
        "registry_url": ctx["registry_url"],
    })


@collectors_router.get("/api/v1/collectors/guide")
async def collector_install_guide(
    request: Request,
    reveal: bool = Query(default=False, description="Admins only: include enrollment secrets"),
    user: Principal = Depends(_require_ops),
) -> JSONResponse:
    if reveal:
        if user.role != Role.ADMIN:
            raise HTTPException(status_code=403, detail="Only administrators can reveal enrollment secrets")
        get_auth_service().audit(
            user,
            "collectors.secrets.reveal",
            "collectors",
            "enrollment",
            ip=request.client.host if request.client else "",
            detail={"fields": sorted(_SECRET_SOURCES)},
        )
    ctx = _guide_context(reveal=reveal, request_host=request.url.hostname)
    return JSONResponse(
        {
            **ctx,
            "guides": _structured_install_guides(ctx),
            "packages": _package_rows(_collectors_root(), ctx),
        },
        headers=_NO_STORE,
    )


@collectors_router.get("/api/v1/collectors/{os_name}/download")
async def download_collector(os_name: str, _: Principal = Depends(_require_ops)) -> StreamingResponse:
    key = os_name.strip().lower()
    if key == "darwin":
        key = "macos"
    if key not in _SUPPORTED:
        raise HTTPException(status_code=404, detail=f"Unknown collector OS: {os_name}")
    root = _collectors_root()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for arcname, rel in _PACKAGE_FILES[key]:
            path = root / rel
            if not path.is_file():
                raise HTTPException(status_code=503, detail=f"Missing package file: {rel}")
            archive.write(path, arcname=arcname)
    buffer.seek(0)
    filename = f"black-onyx-collector-{key}.zip"
    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
