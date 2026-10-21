"""The security capability matrix must carry every field the UI reads.

The Security Lab loads its entire tool picker from
`GET /api/v1/security/capabilities`, which the BFF proxies to the gateway's
`/health/tools`. Two fields had drifted apart from what the browser consumes:

* `parameters` was only on `/v1/tools`, so the argument form rendered empty for
  all 45 tools and required-argument validation never ran.
* `status` was on `/health/tools` but missing from the frontend type, so the
  five disabled capabilities looked runnable and failed with 403 at execution.

Both are shape mismatches between two files that never import each other, so
they are pinned here rather than left to integration testing.
"""

from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GATEWAY_APP = REPO_ROOT / "services" / "security-gateway" / "security_gateway" / "app.py"
SECURITY_CLIENT = REPO_ROOT / "web" / "src" / "detection" / "api" / "security_client.ts"
SECURITY_LAB = REPO_ROOT / "web" / "src" / "workflows_security_lab.tsx"
ROUTES_SECURITY = REPO_ROOT / "src" / "black_onyx" / "api" / "routes_security.py"
TOOLBOX_LOCK = REPO_ROOT / "services" / "security-runner" / "toolbox-build.env"
TOOLBOX_DOCKERFILE = REPO_ROOT / "services" / "security-runner" / "toolbox.Dockerfile"
GUARD_DOCKERFILE = REPO_ROOT / "services" / "security-runner" / "guard.Dockerfile"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "black-onyx-ci.yml"
GATEWAY_CATALOG = REPO_ROOT / "services" / "security-gateway" / "security_gateway" / "tool_catalog.py"
MCP_CATALOG = REPO_ROOT / "black-onyx-tools" / "src" / "black_onyx_tools" / "tools" / "sec_tools.py"

# Fields the browser reads off each tool in the capability matrix.
UI_FIELDS = ["name", "description", "category", "tier", "status", "parameters"]


@pytest.fixture(scope="module")
def gateway_source() -> str:
    return GATEWAY_APP.read_text(encoding="utf-8")


def health_tools_body(source: str) -> str:
    """The `/health/tools` handler body, which builds the matrix."""
    start = source.index('@app.get("/health/tools")')
    end = source.index('@app.get("/health/llm")')
    return source[start:end]


def test_capability_matrix_exposes_every_field_the_ui_reads(gateway_source: str) -> None:
    body = health_tools_body(gateway_source)
    missing = [field for field in UI_FIELDS if f'"{field}"' not in body]
    assert not missing, (
        "the Security Lab reads these off /health/tools and they are not in the "
        f"response: {missing}"
    )


def test_capabilities_route_still_proxies_to_the_tool_matrix() -> None:
    """`/v1/tools` has no tier or status; only `/health/tools` is a full matrix."""
    routes = ROUTES_SECURITY.read_text(encoding="utf-8")
    assert 'path="health/tools"' in routes


def test_frontend_type_declares_status_and_optional_parameters() -> None:
    client = SECURITY_CLIENT.read_text(encoding="utf-8")
    block = client[client.index("export interface SecurityTool"):]
    block = block[: block.index("}")]

    assert re.search(r"\bstatus\?\s*:\s*string", block), "SecurityTool must carry status"
    # Optional, because a gateway predating the fix omits it; the UI must not
    # assume a schema is present.
    assert re.search(r"\bparameters\?\s*:", block), "parameters must be optional-safe"


def test_disabled_capabilities_are_not_runnable_from_the_ui() -> None:
    """A gated tool must be visibly off and its Run button blocked."""
    lab = SECURITY_LAB.read_text(encoding="utf-8")

    assert 'status !== "enabled"' in lab, "the tool list must mark disabled and unavailable capabilities"
    assert "const unavailable" in lab
    # The run path is blocked in both the disabled attribute and the handler,
    # so a keyboard or programmatic activation cannot slip past the attribute.
    assert re.search(r"disabled=\{[^}]*\bunavailable\b", lab), "Run button must be disabled"
    assert re.search(r"if \(unavailable\) \{", lab), "runTool must refuse a disabled tool"


def test_gate_map_and_documented_defaults_agree(gateway_source: str) -> None:
    """Every gated capability fails closed: no gate defaults to enabled."""
    gates = dict(re.findall(r'"(\w+)":\s*"(ENABLE_\w+|SQLMAP_EXPLOIT_MODE)"', gateway_source))
    assert set(gates) == {
        "Bash",
        "hydra_brute",
        "tcpdump_capture",
        "cast_send",
        "sqlmap_scan",
    }, f"unexpected gated tool set: {sorted(gates)}"

    # `_env_flag` reads with a "" default, so an unset flag is false.
    assert 'os.environ.get(name, "")' in gateway_source
    assert 'raise HTTPException(403' in gateway_source


def test_toolbox_release_inputs_and_all_four_security_image_scans_are_locked() -> None:
    values = dict(
        line.split("=", 1)
        for line in TOOLBOX_LOCK.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    assert re.fullmatch(r"debian@sha256:[0-9a-f]{64}", values["TOOLBOX_BASE_IMAGE"])
    assert re.fullmatch(r"debian@sha256:[0-9a-f]{64}", values["GUARD_BASE_IMAGE"])
    assert values["TOOLBOX_DEBIAN_SUITE"] == "sid"  # radare2 is unavailable in bookworm
    assert values["GUARD_DEBIAN_SUITE"] == "sid"
    assert re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", values["DEBIAN_SNAPSHOT"])
    for key in (
        "FOUNDRY_SHA256", "SOLC_SHA256", "NIKTO_SHA256",
        "FILEBYTES_SHA256",
    ):
        assert re.fullmatch(r"[0-9a-f]{64}", values[key])

    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    for image in ("security-toolbox", "security-guard", "security-runner", "security-gateway"):
        assert f'${{RUNNER_TEMP}}/{image}.tar' in workflow
    assert "--scanners vuln,secret,misconfig" in workflow

    assert re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:-[0-9]+)", values["GOBUSTER_DEBIAN_VERSION"])
    for dockerfile, keyring in (
        (TOOLBOX_DOCKERFILE, "debian-archive-keyring.pgp"),
        (GUARD_DOCKERFILE, "debian-archive-keyring.pgp"),
    ):
        source = dockerfile.read_text(encoding="utf-8")
        assert "snapshot.debian.org/archive/debian/%s" in source
        assert f"signed-by=/usr/share/keyrings/{keyring}" in source
        assert "trusted=yes" not in source


def _literal_assignment(path: Path, name: str) -> dict:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {path}")


def _gateway_catalog() -> dict:
    spec = importlib.util.spec_from_file_location("contract_gateway_catalog", GATEWAY_CATALOG)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.TOOL_CATALOG


def _wire_shape(value):
    """Compare behavior-bearing JSON Schema fields, ignoring prose."""
    if isinstance(value, dict):
        normalized = {
            key: _wire_shape(item)
            for key, item in value.items()
            if key != "description" and not (key == "required" and not item)
        }
        return normalized
    if isinstance(value, list):
        return [_wire_shape(item) for item in value]
    return value


def test_official_mcp_executor_schemas_match_gateway_wire_contract() -> None:
    """Client schemas cannot advertise ignored args or omit gateway requirements."""
    gateway = _gateway_catalog()
    mcp = _literal_assignment(MCP_CATALOG, "SECURITY_TOOL_CATALOG")
    assert set(mcp) == set(gateway)

    for name, gateway_spec in gateway.items():
        gateway_schema = gateway_spec["parameters"]
        mcp_schema = mcp[name][1]
        if name == "cast_send":
            gateway_schema = {
                **gateway_schema,
                "properties": {
                    ("sender" if key == "from" else key): value
                    for key, value in gateway_schema["properties"].items()
                },
                "required": [
                    "sender" if key == "from" else key
                    for key in gateway_schema["required"]
                ],
            }
        assert _wire_shape(mcp_schema) == _wire_shape(gateway_schema), name
