"""Deployment invariants that live in the Compose files rather than in code.

These are architecture locks the plan names explicitly one Qdrant, pinned
images, fail-closed secrets and they are enforced nowhere else: a second
`image: qdrant/...` in an overlay, or a `:latest` default slipping into a new
service, would not fail a single test today.

Parsed as YAML text, so they run anywhere. Nothing here needs a Docker daemon.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = sorted(REPO_ROOT.glob("docker-compose*.yml"))


def rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


class ComposeLoader(yaml.SafeLoader):
    """SafeLoader that tolerates Compose's own tags, such as `ports: !reset []`."""


ComposeLoader.add_multi_constructor(
    "!", lambda loader, suffix, node: loader.construct_object(node.__class__(
        tag=loader.resolve(node.__class__, node.value, (True, False)),
        value=node.value,
    ))
)


def services_of(path: Path) -> dict:
    """Services in one Compose file, with `${VAR}` left as written."""
    document = yaml.load(path.read_text(encoding="utf-8"), Loader=ComposeLoader) or {}
    return document.get("services") or {}


@pytest.fixture(scope="module")
def compose() -> list[tuple[Path, dict]]:
    assert COMPOSE_FILES, "no docker-compose files found"
    return [(path, services_of(path)) for path in COMPOSE_FILES]


# ── One Qdrant ────────────────────────────────────────────────────────────


def test_only_one_qdrant_image_is_declared(compose) -> None:
    """Every overlay shares the single `qdrant` service from the base file.

    A second instance would silently split collections in half: writes land in
    one, searches read the other, and nothing errors.
    """
    declarations: list[str] = []
    for path, services in compose:
        for name, spec in services.items():
            image = str((spec or {}).get("image") or "")
            if "qdrant" in image:
                declarations.append(f"{rel(path)}::{name} -> {image}")

    assert len(declarations) == 1, (
        f"expected exactly one Qdrant image declaration, found: {declarations}"
    )
    assert declarations[0].startswith("docker-compose.yml::qdrant"), declarations


def test_overlays_extend_qdrant_rather_than_redefining_it(compose) -> None:
    # docker-compose.host.yml intentionally replaces the bundled Qdrant image
    # with an alpine socat forwarder to an external/host Qdrant.
    allow_redefine = {"docker-compose.host.yml"}
    for path, services in compose:
        if rel(path) in {"docker-compose.yml", *allow_redefine}:
            continue
        spec = services.get("qdrant")
        if spec is None:
            continue
        assert "image" not in (spec or {}), (
            f"{rel(path)} redefines the qdrant image instead of overlaying the base service"
        )


# ── Image pinning ─────────────────────────────────────────────────────────

# `${VAR:-default}` the default is what runs when the operator sets nothing.
INTERPOLATED_DEFAULT = re.compile(r"^\$\{[A-Z0-9_]+:-(?P<default>.+)\}$")

# searxng publishes no stable version tag; it is the one accepted exception and
# is deliberately named so a second one cannot be added silently.
LATEST_ALLOWED = {"searxng/searxng:latest"}


def effective_images(services: dict) -> list[str]:
    images = []
    for spec in services.values():
        image = str((spec or {}).get("image") or "")
        if not image:
            continue
        match = INTERPOLATED_DEFAULT.match(image)
        images.append(match.group("default") if match else image)
    return images


def test_no_unpinned_images_outside_the_known_exception(compose) -> None:
    offenders: list[str] = []
    for path, services in compose:
        for image in effective_images(services):
            if image in LATEST_ALLOWED:
                continue
            if image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]:
                offenders.append(f"{rel(path)} -> {image}")
    assert not offenders, f"unpinned container images: {offenders}"


def test_one_variable_never_has_two_different_defaults(compose) -> None:
    """`${VLLM_IMAGE:-a}` in one file and `${VLLM_IMAGE:-b}` in another means
    the same operator setting produces two different builds."""
    defaults: dict[str, set[str]] = {}
    for path, services in compose:
        for spec in services.values():
            image = str((spec or {}).get("image") or "")
            match = re.match(r"^\$\{(?P<var>[A-Z0-9_]+):-(?P<default>.+)\}$", image)
            if match:
                defaults.setdefault(match.group("var"), set()).add(match.group("default"))

    conflicting = {var: sorted(vals) for var, vals in defaults.items() if len(vals) > 1}
    assert not conflicting, f"image variables with conflicting defaults: {conflicting}"


def test_security_lab_overlay_is_internal_and_profile_labeled() -> None:
    path = REPO_ROOT / "docker-compose.security-lab.yml"
    document = yaml.load(path.read_text(encoding="utf-8"), Loader=ComposeLoader)
    network = document["networks"]["security-lab"]

    assert network["internal"] is True
    assert network["name"] == "blackonyx_anvil"
    assert network["labels"]["com.blackonyx.security-lab-profile"] == "anvil"
    assert {"anvil", "lab-http"} <= set(document["services"])


def test_security_toolbox_contains_anvil_binary() -> None:
    dockerfile = (
        REPO_ROOT / "services" / "security-runner" / "toolbox.Dockerfile"
    ).read_text(encoding="utf-8")

    assert "cast forge anvil" in dockerfile


def test_bootstrap_uses_only_a_real_external_cape_lab() -> None:
    script = (REPO_ROOT / "scripts" / "bootstrap_full_stack.sh").read_text(encoding="utf-8")
    ps1 = (REPO_ROOT / "scripts" / "bootstrap_full_stack.ps1").read_text(encoding="utf-8")

    for text in (script, ps1):
        assert "CAPE_URL" in text
        assert "cape-lab" not in text and "cape-kvm" not in text
    for removed in (
        "docker-compose.detection-cape-kvm.yml",
        "docker-compose.detection-cape-lab.yml",
        "services/malware-lab-stub",
        "services/malware-cape-kvm",
    ):
        assert not (REPO_ROOT / removed).exists(), removed


# ── Secrets fail closed ───────────────────────────────────────────────────

# `${VAR:?message}` refuses to render without a value. Most keys here are
# deliberately optional an absent OPENAI_API_KEY or INCIDENT_API_SERVICE_KEY
# means "that integration is not deployed", and the application fails closed on
# it at request time rather than at compose time. So this does not demand that
# every secret be required; it pins the ones that already are, because
# downgrading one of them to `:-` turns a refused deploy into a silently
# unauthenticated service.
REQUIRED_SECRETS = {
    "ASSET_REGISTRY_SERVICE_KEY",
    "BLACK_ONYX_ALLOWED_HOSTS",
    "BLACK_ONYX_AUTH_SECRET",
    "BLACK_ONYX_DETECTION_TENANT",
    "BLACK_ONYX_EXTERNAL_URL",
    "BLACK_ONYX_HOSTNAME",
    "SECURITY_GATEWAY_KEY",
    "SECURITY_RUNNER_TOKEN",
    "SECURITY_SANDBOX_IMAGE",
    "SELF_MONITOR_TENANT_ID",
    # training-worker (deploy/detection/compose/docker-compose.apps.yml) signs
    # training artifacts and cannot degrade without this key; an unset value
    # used to crash-loop the container forever instead of failing at deploy time.
    "TRAINING_ARTIFACT_SIGNING_KEY",
}


def test_variables_that_refuse_to_render_without_a_value_stay_that_way() -> None:
    # Scans included files too: TRAINING_ARTIFACT_SIGNING_KEY is only declared
    # in deploy/detection/compose/docker-compose.apps.yml, reached from
    # docker-compose.detection-apps.yml via `include:`, not in COMPOSE_FILES.
    raw = "\n".join(path.read_text(encoding="utf-8") for path in all_compose_files())
    still_required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", raw))

    downgraded = sorted(REQUIRED_SECRETS - still_required)
    assert not downgraded, (
        "these no longer refuse to render without a value, so the stack would "
        f"start unauthenticated instead of failing: {downgraded}"
    )


def test_checkpoint_volume_owner_initializer_is_scoped_and_precedes_app_start() -> None:
    services = services_of(REPO_ROOT / "docker-compose.yml")
    initializer = services["state-permissions"]
    assert initializer["user"] == "0:0"
    assert initializer["read_only"] is True
    assert initializer["network_mode"] == "none"
    assert initializer["cap_drop"] == ["ALL"]
    assert initializer["cap_add"] == ["CHOWN"]
    assert initializer["volumes"] == ["checkpoints_data:/app/.checkpoints"]
    assert "no-new-privileges:true" in initializer["security_opt"]
    assert initializer["entrypoint"] == [
        "/app/.venv/bin/python",
        "/app/scripts/fix_checkpoint_volume_owner.py",
    ]
    for name in ("web", "cli"):
        assert services[name]["depends_on"]["state-permissions"]["condition"] == (
            "service_completed_successfully"
        )


def test_security_sessions_owner_initializer_is_scoped_and_precedes_runner() -> None:
    services = services_of(REPO_ROOT / "docker-compose.security-tools.yml")
    initializer = services["security-sessions-permissions"]
    assert initializer["user"] == "0:0"
    assert initializer["read_only"] is True
    assert initializer["network_mode"] == "none"
    assert initializer["cap_drop"] == ["ALL"]
    assert initializer["cap_add"] == ["CHOWN"]
    assert initializer["volumes"] == [
        "${SECURITY_SESSIONS_HOST_ROOT:?Set an absolute host sessions directory}:/workspace"
    ]
    assert "no-new-privileges:true" in initializer["security_opt"]
    assert initializer["entrypoint"] == [
        "/usr/local/bin/python",
        "/usr/local/lib/black-onyx/fix_security_sessions_owner.py",
    ]
    assert services["security-runner"]["depends_on"]["security-sessions-permissions"][
        "condition"
    ] == "service_completed_successfully"


def test_the_runner_sandbox_image_is_required_and_digest_pinned() -> None:
    """The runner refuses a tag-only image at runtime; compose must supply one.

    Paired with `services/security-runner/tests/test_isolation.py`, which
    asserts the refusal itself.
    """
    raw = "\n".join(path.read_text(encoding="utf-8") for path in COMPOSE_FILES)
    assert "${SECURITY_SANDBOX_IMAGE:?" in raw


# ── Build context completeness ────────────────────────────────────────────


def dockerfiles() -> list[Path]:
    found = [
        path
        for path in REPO_ROOT.rglob("Dockerfile")
        if ".venv" not in path.parts
        and "node_modules" not in path.parts
        and "Archive" not in path.parts
        and "build" not in path.parts
    ]
    assert found, "no Dockerfiles found"
    return found


def dockerignore_rules() -> tuple[list[str], list[str]]:
    """(excluded, re-included) patterns, comments and blanks dropped."""
    excluded: list[str] = []
    negated: list[str] = []
    for line in (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines():
        rule = line.strip()
        if not rule or rule.startswith("#"):
            continue
        (negated if rule.startswith("!") else excluded).append(rule.lstrip("!"))
    return excluded, negated


COPY_SOURCE = re.compile(r"^COPY\s+(?:--[\w=:.-]+\s+)*(?P<src>[^\s]+)", re.MULTILINE)


def test_every_dockerfile_copy_source_survives_the_build_context() -> None:
    """A COPY from an excluded directory aborts the build, it does not skip it.

    `.dockerignore` excluded `detection` and `contracts` wholesale while six
    service images COPY out of them, so `docker compose --build` failed with
    "/detection/profiles: not found" and took the detection-runtime-smoke CI
    job with it. Each required path now needs an explicit negation, and this
    fails the moment a new COPY reaches past one.
    """
    excluded, negated = dockerignore_rules()
    offenders: list[str] = []

    for dockerfile in dockerfiles():
        text = dockerfile.read_text(encoding="utf-8")
        for match in COPY_SOURCE.finditer(text):
            src = match.group("src")
            # Sources from an earlier build stage never touch the context.
            if src.startswith(("/", "--")) or "=" in src:
                continue
            parts = Path(src.rstrip("/")).parts
            if not parts:
                continue
            top = parts[0]
            if top not in excluded:
                continue
            # The path, or any parent of it, must be re-included.
            candidates = {
                "/".join(parts[:depth]) for depth in range(1, len(parts) + 1)
            }
            if not candidates & set(negated):
                offenders.append(f"{dockerfile.relative_to(REPO_ROOT).as_posix()} -> {src}")

    assert not offenders, (
        "these COPY sources are excluded from the build context, so the image "
        f"cannot build: {offenders}"
    )


# ── Local workspace packages reach the image ──────────────────────────────


def local_workspace_packages() -> dict[str, str]:
    """Distribution name -> directory under packages/ for every workspace package."""
    import tomllib

    packages: dict[str, str] = {}
    for pyproject in (REPO_ROOT / "packages").glob("*/pyproject.toml"):
        name = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["name"]
        packages[name] = pyproject.parent.name
    assert packages, "no workspace packages found under packages/"
    return packages


def test_every_declared_workspace_package_is_installed_by_the_image() -> None:
    """A local dependency must be COPYed and pip-installed before `pip install .`.

    `uv sync` resolves black-onyx-* packages from packages/ through
    [tool.uv.sources], so a service's tests pass whether or not its Dockerfile
    installs them. pip inside the image has no such mapping.
    training-orchestrator declared black-onyx-calibration without installing it,
    and the build aborted with "No matching distribution found" -- which took
    every other detection image down with it under `compose build`.
    """
    import tomllib

    workspace = local_workspace_packages()
    offenders: list[str] = []
    manifests = sorted(
        [*REPO_ROOT.glob("services/*/pyproject.toml"), *REPO_ROOT.glob("detection/models/*/pyproject.toml")]
    )
    assert manifests, "no service manifests found"

    for pyproject in manifests:
        dockerfile = pyproject.parent / "Dockerfile"
        if not dockerfile.is_file():
            continue
        declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"].get("dependencies", [])
        image_text = dockerfile.read_text(encoding="utf-8")
        for requirement in declared:
            name = re.split(r"[<>=!~\[;\s]", requirement, maxsplit=1)[0]
            if name not in workspace:
                continue
            source = f"packages/{workspace[name]}"
            copied = re.search(rf"^COPY\s+(?:--[\w=:.-]+\s+)*{re.escape(source)}\b", image_text, re.MULTILINE)
            installed = re.search(rf"pip install[^\n]*/packages/{re.escape(workspace[name])}\b", image_text)
            if not (copied and installed):
                offenders.append(f"{rel(dockerfile)}: declares {name} but does not COPY and install {source}")

    assert not offenders, offenders


# ── Health-gated dependencies can actually become healthy ─────────────────


def all_compose_files() -> list[Path]:
    """Every root compose file plus every file reachable through `include:`.

    docker-compose.detection-apps.yml is a thin `include:` wrapper around
    deploy/detection/compose/docker-compose.apps.yml, where the ~30 detection
    microservices are actually declared. A scan limited to COMPOSE_FILES misses
    that file entirely, which is how a required secret declared only there
    (TRAINING_ORCHESTRATOR_ARTIFACT_SIGNING_KEY) went unchecked.
    """
    found: list[Path] = []
    queue = list(COMPOSE_FILES)
    seen: set[Path] = set()
    while queue:
        path = queue.pop(0).resolve()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        found.append(path)
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=ComposeLoader) or {}
        for entry in document.get("include") or []:
            target = entry.get("path") if isinstance(entry, dict) else entry
            for item in target if isinstance(target, list) else [target]:
                queue.append(path.parent / item)
    return found


def merged_services() -> dict[str, dict]:
    """Every service across the root compose files and the files they include.

    Later definitions are merged over earlier ones key by key, which is how a
    `healthcheck` added in one overlay reaches a service declared in another.
    """
    merged: dict[str, dict] = {}
    for path in all_compose_files():
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=ComposeLoader) or {}
        for name, spec in (document.get("services") or {}).items():
            merged.setdefault(name, {}).update(spec or {})
    return merged


def test_service_healthy_dependencies_have_a_healthcheck() -> None:
    """`condition: service_healthy` on a service with no healthcheck never resolves.

    Compose refuses to start the dependent container ("has no healthcheck
    configured"). training-orchestrator waited on MLflow this way while the
    MLflow service defined no healthcheck and its image ships none, so the
    service could not be started from docker-compose.detection-apps.yml at all.
    """
    services = merged_services()
    offenders: list[str] = []
    for name, spec in services.items():
        depends = spec.get("depends_on") or {}
        if not isinstance(depends, dict):
            continue
        for dependency, condition in depends.items():
            if not isinstance(condition, dict) or condition.get("condition") != "service_healthy":
                continue
            healthcheck = (services.get(dependency) or {}).get("healthcheck") or {}
            if not healthcheck or healthcheck.get("disable"):
                offenders.append(f"{name} waits for {dependency} to be healthy, but {dependency} has no healthcheck")

    assert not offenders, offenders
