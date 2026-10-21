#!/usr/bin/env python3
"""Generate deployment-setting metadata from supported Compose manifests.

Review the generated metadata after Compose changes. Environment values are
listed here so the deployment controller can expose and validate them; secret
values are always write-only in the settings API.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "src" / "black_onyx" / "compose_setting_inventory.py"
MANIFESTS = sorted(ROOT.glob("docker-compose*.yml")) + sorted(
    (ROOT / "deploy" / "detection" / "compose").glob("docker-compose*.yml")
)
EXISTING = (ROOT / "src" / "black_onyx" / "settings_registry.py").read_text(encoding="utf-8")
PLACEHOLDER = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::([-?])([^}]*))?\}")
SERVICE = re.compile(r"^  ([a-z][a-z0-9-]+):\s*$")
SECRET = re.compile(r"(?:^|_)(?:API_KEY|SERVICE_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY|ACCESS_KEY)$")
FLAG_SUFFIXES = ("_ENABLED", "_DISABLED", "_STARTTLS", "_HEARTBEAT")


def category(name: str) -> str:
    if name in {"OIDC_DISABLED", "ALLOW_DEMO_KEYS"} or name.startswith("BLACK_ONYX_AUTH"):
        return "authentication"
    if name.startswith(("SECURITY_", "TOOL_", "ENABLE_")):
        return "security tools"
    if name.startswith(("NOTIFICATION_", "SMTP_")):
        return "notifications"
    if name.startswith(("SELF_MONITOR_",)):
        return "observability"
    if name.startswith(("TRAINING_", "MODEL_", "CODE_PROCESSOR_", "CODE_ENRICHMENT_", "VLLM_")) or "ARTIFACTS_DIR" in name or name in {"HUGGING_FACE_HUB_TOKEN", "BLACK_ONYX_5B_WEIGHTS", "VECTOR_SEARCH_ENABLED"}:
        return "model/training"
    if name.startswith("LLM_") or name in {"TEMPERATURE", "MAX_TOKENS"}:
        return "providers"
    if name.endswith(("_URL", "_ENDPOINT", "_HOSTNAME", "_ALLOWED_HOSTS")):
        return "routing"
    if name.endswith(("_PORT", "_LIMIT")) or name in {
        "POSTGRES_PASSWORD", "REDIS_PASSWORD", "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
        "OPENSEARCH_INITIAL_ADMIN_PASSWORD", "SEARXNG_SECRET", "APP_CPU_LIMIT", "APP_MEMORY_LIMIT",
    }:
        return "infrastructure"
    if name.endswith(("_API_KEY", "_SERVICE_KEY", "_TOKEN", "_WEBHOOK_URL")):
        return "connectors"
    return "deployment"


def humanize(name: str) -> str:
    return name.lower().replace("_", " ").capitalize()


def collect() -> dict[str, dict[str, object]]:
    values: dict[str, dict[str, object]] = {}
    for manifest in MANIFESTS:
        in_services = False
        service = "compose"
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if re.match(r"^services:\s*$", line):
                in_services = True
                continue
            if in_services and re.match(r"^[^\s#][^:]*:\s*(?:#.*)?$", line):
                in_services = False
            if in_services:
                service_match = SERVICE.match(line)
                if service_match:
                    service = service_match.group(1)
            for match in PLACEHOLDER.finditer(line):
                name, operation, default = match.groups()
                if name.startswith("QDRANT_") or f'"{name}"' in EXISTING:
                    continue
                item = values.setdefault(name, {"consumers": set(), "defaults": set()})
                if service == "compose":
                    item["consumers"].update(("black-onyx", "cli"))
                else:
                    item["consumers"].add(service)
                if operation == "-" and default and "$" not in default:
                    item["defaults"].add(default)
    return values


def render() -> str:
    rows = []
    for name, item in sorted(collect().items()):
        defaults = item["defaults"]
        default = next(iter(defaults)) if len(defaults) == 1 else None
        consumers = tuple(sorted(item["consumers"]))
        is_secret = bool(SECRET.search(name))
        if is_secret and default is not None:
            # Preserve the fact that Compose has a default without duplicating
            # a credential value in this generated inventory.
            default = "__COMPOSE_SECRET_DEFAULT_CONFIGURED__"
        flags = name.endswith(FLAG_SUFFIXES) or name.startswith(("ALLOW_", "ENABLE_")) or name in {
            "OIDC_DISABLED", "FEDERATED_HUNT_ENABLED", "VECTOR_SEARCH_ENABLED",
            "MODEL_SERVING_ENABLED", "TRAINING_ALLOW_SYNCHRONOUS", "TRAINING_ALLOW_SYNTHETIC",
        }
        choices = ("true", "false") if flags else None
        required = "false" if name in {"OIDC_DISABLED", "ALLOW_DEMO_KEYS"} else None
        description = f"Compose setting consumed by {', '.join(consumers)}."
        rows.append(
            "    ("
            f"{name!r}, {category(name)!r}, {consumers!r}, {description!r}, "
            f"{is_secret!r}, {default!r}, {required!r}, {choices!r}),"
        )
    return (
        '"""Generated Compose deployment-setting metadata; regenerate with scripts/generate_compose_setting_inventory.py."""\n'
        "from __future__ import annotations\n\n"
        "COMPOSE_DEPLOYMENT_SETTING_SPECS = (\n"
        + "\n".join(rows)
        + "\n)\n"
    )


def main() -> None:
    OUTPUT.write_text(render(), encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
