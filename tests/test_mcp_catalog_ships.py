"""The MCP tool catalog has to reach the deployed image, not just the repo.

`test_mcp_registry.py` asserts the catalog holds 63 tools, and it passes -- it
runs from a checkout where `black-onyx-tools/` is present. The container told a
different story: `.dockerignore` excluded the whole directory and the image
installed `--extra image --extra llm --extra threat-intel` without `--extra
mcp`, so the running application loaded **zero** tools. The agent loop and the
MCP orchestrator both consume that catalog, and `/api/v1/info` reports its size.

A green test suite and an empty production registry is exactly the gap these
close: they assert the packaging, not the source tree.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
PYPROJECT = REPO_ROOT / "pyproject.toml"
CATALOG = REPO_ROOT / "black-onyx-tools" / "datasets" / "tool_use" / "tools.json"

# The shipped contract includes executors plus official-client lifecycle controls.
EXPECTED_PLATFORM = 18
EXPECTED_SECURITY = 49


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dockerignore_lines() -> list[str]:
    return [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_catalog_on_disk_holds_the_contracted_tool_counts() -> None:
    entries = json.loads(CATALOG.read_text(encoding="utf-8"))
    names = [(entry.get("function") or {}).get("name") for entry in entries]
    security = [name for name in names if name and name.startswith("sec_")]
    platform = [name for name in names if name and not name.startswith("sec_")]

    assert len(entries) == EXPECTED_PLATFORM + EXPECTED_SECURITY
    assert len(security) == EXPECTED_SECURITY
    assert len(platform) == EXPECTED_PLATFORM
    assert len(set(names)) == len(names), "duplicate tool name in the catalog"


def test_registry_resolves_the_catalog_where_the_image_places_it() -> None:
    """registry.py walks up three parents from its own file to find the catalog.

    The Dockerfile puts `src/` at /app/src, so parents[3] is /app and the
    catalog must land at /app/black-onyx-tools/datasets/tool_use/tools.json.
    Pinning the relative shape here means a source move that breaks the
    container path fails in CI rather than at runtime.
    """
    from black_onyx.mcp import registry

    resolved = Path(registry.__file__).resolve().parents[3]
    assert (resolved / "black-onyx-tools" / "datasets" / "tool_use" / "tools.json") == CATALOG


def test_image_installs_the_mcp_extra(dockerfile: str) -> None:
    """Without `--extra mcp` the tool implementations are simply absent."""
    sync_lines = [line for line in dockerfile.splitlines() if "uv sync" in line or "--extra" in line]
    extras_lines = [line for line in sync_lines if "--extra" in line]
    assert extras_lines, "no --extra flags found in the Dockerfile"
    for line in extras_lines:
        assert "--extra mcp" in line, f"sync without the mcp extra: {line.strip()}"


def test_image_copies_the_tool_package_and_catalog(dockerfile: str) -> None:
    copied = "\n".join(line for line in dockerfile.splitlines() if line.startswith("COPY"))
    assert "black-onyx-tools/src/" in copied, "tool implementations are not copied in"
    assert "datasets/tool_use/tools.json" in copied, "the catalog is not copied in"
    assert "black-onyx-tools/pyproject.toml" in copied, (
        "the local path dependency cannot install without its pyproject"
    )


def test_dockerignore_lets_the_tool_package_through(dockerignore_lines: list[str]) -> None:
    """A blanket `black-onyx-tools` exclusion silently empties the registry."""
    assert "black-onyx-tools" in dockerignore_lines, "expected the broad exclusion to remain"
    for required in (
        "!black-onyx-tools/src",
        "!black-onyx-tools/pyproject.toml",
        "!black-onyx-tools/datasets/tool_use/tools.json",
    ):
        assert required in dockerignore_lines, f"missing negation: {required}"

    # The heavy local artefacts stay out: .venv alone is ~68 MB.
    for excluded in ("black-onyx-tools/.venv", "black-onyx-tools/build"):
        assert excluded in dockerignore_lines, f"missing exclusion: {excluded}"


def test_mcp_extra_still_declares_the_tool_package() -> None:
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    extras = config["project"]["optional-dependencies"]
    assert "black-onyx-tools" in extras["mcp"]

    sources = config["tool"]["uv"]["sources"]["black-onyx-tools"]
    assert sources["path"] == "black-onyx-tools", (
        "the mcp extra installs from this path; the Dockerfile COPY must match it"
    )


def test_negations_come_after_the_exclusion_they_reverse() -> None:
    """Docker applies ignore rules in order: a negation above its exclusion is dead."""
    text = DOCKERIGNORE.read_text(encoding="utf-8")
    broad = re.search(r"^black-onyx-tools$", text, re.MULTILINE)
    negation = re.search(r"^!black-onyx-tools/src$", text, re.MULTILINE)
    assert broad and negation
    assert broad.start() < negation.start(), (
        "the !black-onyx-tools/src negation must follow the broad exclusion to take effect"
    )


def test_catalog_policy_and_handlers_agree_on_every_tool_name() -> None:
    """One typo in a name silently disables a tool.

    Three platform tools shipped without the `black_onyx_` prefix that the
    other fifteen use. The catalog advertised the bare names, so the model was
    offered `certificate_transparency`, `passive_dns_whois` and
    `url_screenshot_sandbox` -- while `validate_tool_call` knew only the
    prefixed forms and failed closed on anything unknown. All three were dead
    on arrival, and no test noticed because each layer was internally
    consistent and counted 63.
    """
    from black_onyx.mcp.registry import _TOOL_MODULES, load_tool_catalog
    from black_onyx.mcp.tool_policy import TOOL_TIERS

    catalog = {(entry.get("function") or {}).get("name") for entry in load_tool_catalog()}
    tiers = set(TOOL_TIERS)
    handlers = set(_TOOL_MODULES)

    assert catalog - tiers == set(), f"advertised but unknown to the policy: {sorted(catalog - tiers)}"
    assert tiers - catalog == set(), f"policy knows a tool the catalog never offers: {sorted(tiers - catalog)}"
    assert handlers - catalog == set(), f"handler with no catalog entry: {sorted(handlers - catalog)}"


def test_every_platform_tool_uses_the_black_onyx_prefix() -> None:
    """The naming convention that keeps platform and security tools apart."""
    from black_onyx.mcp.registry import load_tool_catalog

    names = [(entry.get("function") or {}).get("name") for entry in load_tool_catalog()]
    platform = [name for name in names if name and not name.startswith("sec_")]

    assert len(platform) == EXPECTED_PLATFORM
    unprefixed = sorted(name for name in platform if not name.startswith("black_onyx_"))
    assert not unprefixed, f"platform tools missing the black_onyx_ prefix: {unprefixed}"


def test_the_generator_reproduces_the_full_catalog() -> None:
    """Re-running the documented regeneration must not drop the security half.

    generate_examples.py is the only writer of tools.json and used to emit just
    the 18 platform tools, so the documented regeneration step rewrote the file
    and destroyed the sec_* entries -- which nothing in the repository could
    restore.
    """
    generator = (
        REPO_ROOT / "black-onyx-tools" / "datasets" / "tool_use" / "generate_examples.py"
    ).read_text(encoding="utf-8")

    assert "def security_tool_defs()" in generator
    assert "SECURITY_TOOL_CATALOG" in generator, (
        "the generator must build the sec_* half from the in-code catalog"
    )
    assert "TOOLS + security_tools" in generator, (
        "tools.json must be written as platform + security, not platform alone"
    )
