#!/usr/bin/env python3
"""Register a local model directory with aliases via MLflow or a local JSON registry."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_ALIASES = ("champion", "canary", "shadow", "candidate")


def _local_registry_path(registry_file: Path) -> Path:
    registry_file.parent.mkdir(parents=True, exist_ok=True)
    if not registry_file.exists():
        registry_file.write_text(json.dumps({"models": {}}, indent=2) + "\n", encoding="utf-8")
    return registry_file


def register_local(
    model_dir: Path,
    model_name: str,
    version: str,
    aliases: list[str],
    registry_file: Path,
) -> dict[str, Any]:
    path = _local_registry_path(registry_file)
    data = json.loads(path.read_text(encoding="utf-8"))
    models = data.setdefault("models", {})
    entry = models.setdefault(model_name, {"versions": {}, "aliases": {}})
    entry["versions"][version] = {
        "path": str(model_dir.resolve()),
        "registered_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    for alias in aliases:
        entry["aliases"][alias] = version
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "backend": "local-json",
        "model_name": model_name,
        "version": version,
        "aliases": {a: version for a in aliases},
        "registry_file": str(path),
    }


def register_mlflow(
    model_dir: Path,
    model_name: str,
    version: str,
    aliases: list[str],
    tracking_uri: str | None,
) -> dict[str, Any]:
    import mlflow
    from mlflow.tracking import MlflowClient

    if tracking_uri:
        mlflow.set_tracking_uri(tracking_uri)
    client = MlflowClient()
    try:
        client.get_registered_model(model_name)
    except Exception:  # noqa: BLE001 - create if missing across mlflow versions
        client.create_registered_model(model_name)

    result = mlflow.register_model(
        model_uri=f"file://{model_dir.resolve().as_posix()}",
        name=model_name,
    )
    # Prefer requested version tag via alias mapping; MLflow assigns its own version number.
    mlflow_version = str(result.version)
    for alias in aliases:
        client.set_registered_model_alias(model_name, alias, mlflow_version)
    return {
        "backend": "mlflow",
        "model_name": model_name,
        "version": mlflow_version,
        "requested_version": version,
        "aliases": {a: mlflow_version for a in aliases},
        "source": str(model_dir.resolve()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--model-name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--alias",
        action="append",
        dest="aliases",
        default=None,
        help="Alias to set (repeatable). Defaults to champion.",
    )
    parser.add_argument("--tracking-uri", default=None)
    parser.add_argument(
        "--registry-file",
        type=Path,
        default=Path(".mlflow-local-registry.json"),
        help="Fallback local registry JSON path when mlflow is unavailable",
    )
    parser.add_argument(
        "--force-local",
        action="store_true",
        help="Skip mlflow and write the local JSON registry",
    )
    args = parser.parse_args(argv)

    if not args.model_dir.is_dir():
        print(f"model dir not found: {args.model_dir}", file=sys.stderr)
        return 2

    aliases = args.aliases or ["champion"]
    for alias in aliases:
        if alias not in DEFAULT_ALIASES:
            print(f"unsupported alias: {alias}", file=sys.stderr)
            return 2

    if not args.force_local:
        try:
            result = register_mlflow(
                args.model_dir,
                args.model_name,
                args.version,
                aliases,
                args.tracking_uri,
            )
            print(json.dumps(result, indent=2))
            return 0
        except ImportError:
            pass
        except Exception as exc:  # noqa: BLE001
            print(
                f"mlflow registration failed ({exc}); falling back to local registry",
                file=sys.stderr,
            )

    result = register_local(
        args.model_dir,
        args.model_name,
        args.version,
        aliases,
        args.registry_file,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
