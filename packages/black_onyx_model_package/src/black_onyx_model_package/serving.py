"""Serve signed model packages per alias and keep replicas in sync.

The training orchestrator owns *desired* serving state (alias → version →
package signature). Each model-service replica runs a :class:`ServingSync`
that polls that state, downloads any package it is not yet serving, verifies
its signature and identity, loads it through the service's own loader, swaps
it into the alias slot atomically, and reports what it actually serves.
Promotion in the orchestrator commits only after replicas confirm, so the
alias row always describes a version that is loaded somewhere.

Transport format: an uncompressed tar of the flat package directory.
"""
from __future__ import annotations

import io
import json
import logging
import os
import shutil
import socket
import tarfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Generic, TypeVar

from black_onyx_model_package.package import verify_model_package

logger = logging.getLogger(__name__)

T = TypeVar("T")
ALIASES = ("champion", "canary", "shadow")
MAX_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024


def package_signature(package_dir: Path) -> str:
    """The package's HMAC signature, used as its immutable identity."""
    signed = json.loads((package_dir / "signature.json").read_text(encoding="utf-8"))
    return str(signed["signature"])


def pack_package(package_dir: Path) -> bytes:
    """Tar a flat package directory (no subdirectories or links allowed)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path in sorted(package_dir.iterdir()):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Model package entry is not a regular file: {path.name}")
            archive.add(path, arcname=path.name, recursive=False)
    return buffer.getvalue()


def unpack_package(blob: bytes, destination: Path) -> None:
    """Extract a package tar, refusing anything but flat regular files."""
    if len(blob) > MAX_PACKAGE_BYTES:
        raise ValueError("Model package is too large")
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as archive:
        for member in archive.getmembers():
            name = member.name
            if (
                not member.isfile() or "/" in name or "\\" in name or name in {"", ".", ".."}
                or name.startswith(".")
            ):
                raise ValueError(f"Unsafe model package member: {name!r}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"Unreadable model package member: {name!r}")
            with (destination / name).open("xb") as target:
                shutil.copyfileobj(source, target)


@dataclass
class Slot(Generic[T]):
    alias: str
    version: str
    signature: str
    model: T
    path: Path
    loaded_at: str
    generation: int = 0


class ServingRegistry(Generic[T]):
    """Holds one verified, loaded package per alias."""

    def __init__(
        self,
        model_name: str,
        loader: Callable[[Path], T],
        *,
        signing_key: str,
        root: Path,
    ) -> None:
        self.model_name = model_name
        self._loader = loader
        self._signing_key = signing_key
        self.root = root
        self._slots: dict[str, Slot[T]] = {}
        self._generations: dict[str, int] = {}
        self._error_generations: dict[str, int] = {}
        self._lock = threading.RLock()
        self.errors: dict[str, str] = {}

    def load_package(
        self, alias: str, version: str, blob: bytes, expected_signature: str | None = None,
        generation: int = 0,
    ) -> Slot[T]:
        if alias not in ALIASES:
            raise ValueError(f"unsupported alias: {alias}")
        staging = self.root / "packages" / f"{version}-{uuid.uuid4().hex[:8]}"
        try:
            unpack_package(blob, staging)
            verify_model_package(staging, self._signing_key, expected_model_name=self.model_name)
            config = json.loads((staging / "config.json").read_text(encoding="utf-8"))
            if config.get("model_version") != version:
                raise ValueError("Model package version does not match the requested version")
            signature = package_signature(staging)
            if expected_signature and signature != expected_signature:
                raise ValueError("Model package signature does not match desired state")
            model = self._loader(staging)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        slot = Slot(alias, version, signature, model, staging, datetime.now(timezone.utc).isoformat(), generation)
        with self._lock:
            if generation < self._generations.get(alias, 0):
                shutil.rmtree(staging, ignore_errors=True)
                raise ValueError("stale serving generation cannot replace the current alias")
            previous = self._slots.get(alias)
            self._slots[alias] = slot
            self._generations[alias] = generation
            self._error_generations.pop(alias, None)
            self.errors.pop(alias, None)
        self._persist()
        if previous is not None and previous.path != staging and not self._path_in_use(previous.path):
            shutil.rmtree(previous.path, ignore_errors=True)
        return slot

    def _path_in_use(self, path: Path) -> bool:
        with self._lock:
            return any(slot.path == path for slot in self._slots.values())

    def unload(self, alias: str, generation: int | None = None) -> None:
        with self._lock:
            current_generation = self._generations.get(alias, 0)
            if generation is not None and generation < current_generation:
                return
            slot = self._slots.pop(alias, None)
            if generation is not None:
                self._generations[alias] = generation
            self.errors.pop(alias, None)
            self._error_generations.pop(alias, None)
        self._persist()
        if slot is not None and not self._path_in_use(slot.path):
            shutil.rmtree(slot.path, ignore_errors=True)

    def confirm_loaded_generation(self, alias: str, generation: int) -> bool:
        """Fence an unchanged, already verified package at a newer generation."""
        with self._lock:
            if generation < self._generations.get(alias, 0):
                return False
            slot = self._slots.get(alias)
            if slot is None:
                return False
            slot.generation = generation
            self._generations[alias] = generation
            self.errors.pop(alias, None)
            self._error_generations.pop(alias, None)
        self._persist()
        return True

    def get(self, alias: str | None) -> Slot[T] | None:
        """Canary/shadow fall back to champion when no separate package is loaded."""
        with self._lock:
            if alias and alias in self._slots:
                return self._slots[alias]
            return self._slots.get("champion")

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "model_name": self.model_name,
                "slots": {
                    alias: {
                        "version": slot.version, "signature": slot.signature,
                        "loaded_at": slot.loaded_at, "generation": slot.generation,
                    }
                    for alias, slot in self._slots.items()
                },
                "generations": dict(self._generations),
                "error_generations": dict(self._error_generations),
                "errors": dict(self.errors),
            }

    def _persist(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        state = {
            "slots": {
                alias: {
                    "version": slot.version, "signature": slot.signature,
                    "path": slot.path.name, "generation": slot.generation,
                }
                for alias, slot in self._slots.items()
            },
            "generations": self._generations,
        }
        tmp = self.root / "serving-state.json.tmp"
        tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.root / "serving-state.json")

    def restore(self) -> None:
        """Reload previously served packages after a restart (re-verified)."""
        state_path = self.root / "serving-state.json"
        if not state_path.is_file():
            return
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        entries = state.get("slots", state) if isinstance(state, dict) else {}
        generations = state.get("generations", {}) if isinstance(state, dict) else {}
        for alias, entry in entries.items():
            if alias not in ALIASES or not isinstance(entry, dict):
                continue
            path = self.root / "packages" / str(entry.get("path", ""))
            try:
                verify_model_package(path, self._signing_key, expected_model_name=self.model_name)
                if package_signature(path) != entry.get("signature"):
                    raise ValueError("restored package signature changed")
                model = self._loader(path)
            except Exception as exc:  # noqa: BLE001
                self.errors[alias] = f"restore failed: {exc}"
                continue
            with self._lock:
                generation = int(entry.get("generation", generations.get(alias, 0)))
                self._slots[alias] = Slot(
                    alias, entry["version"], entry["signature"], model, path,
                    datetime.now(timezone.utc).isoformat(), generation,
                )
                self._generations[alias] = generation
        with self._lock:
            for alias, generation in generations.items():
                if alias in ALIASES:
                    self._generations[alias] = max(int(generation), self._generations.get(alias, 0))


class ServingSync:
    """Poll desired state from the training orchestrator and converge."""

    def __init__(
        self,
        registry: ServingRegistry[Any],
        *,
        orchestrator_url: str,
        api_key: str,
        tenant_id: str,
        interval_s: float = 15.0,
        instance_id: str | None = None,
        http: Any | None = None,
    ) -> None:
        self.registry = registry
        self.url = orchestrator_url.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.interval_s = interval_s
        self.instance_id = instance_id or f"{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
        self._http = http
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _client(self) -> Any:
        if self._http is None:
            import httpx

            self._http = httpx.Client(timeout=120.0, trust_env=False)
        return self._http

    def _headers(self) -> dict[str, str]:
        return {"X-Service-Key": self.api_key, "X-API-Key": self.api_key, "X-Tenant-Id": self.tenant_id}

    def sync_once(self) -> dict[str, Any]:
        model = self.registry.model_name
        response = self._client().get(
            f"{self.url}/api/v1/serving/{model}/desired", headers=self._headers(),
        )
        response.raise_for_status()
        desired = response.json().get("aliases", {})
        loaded = self.registry.status()["slots"]
        # Desired state is a complete map: aliases omitted by the orchestrator
        # must be unloaded so failed first promotions and rollbacks converge.
        for alias in ALIASES:
            target = desired.get(alias)
            if target is None:
                if alias in loaded:
                    self.registry.unload(alias)
                continue
            generation = int(target.get("generation", 0))
            if target.get("removed") or not target.get("version") or not target.get("signature"):
                self.registry.unload(alias, generation)
                continue
            version, signature = str(target["version"]), str(target["signature"])
            current = loaded.get(alias)
            if (current and current["version"] == version and current["signature"] == signature
                    and int(current.get("generation", 0)) <= generation):
                self.registry.confirm_loaded_generation(alias, generation)
                continue
            if generation < int(self.registry.status()["generations"].get(alias, 0)):
                continue
            try:
                package = self._client().get(
                    f"{self.url}/api/v1/models/{model}/versions/{version}/package",
                    headers=self._headers(),
                )
                package.raise_for_status()
                self.registry.load_package(
                    alias, version, package.content, expected_signature=signature, generation=generation,
                )
            except Exception as exc:  # noqa: BLE001
                self.registry.errors[alias] = f"{version}: {exc}"
                self.registry._error_generations[alias] = generation
                self.registry._persist()
                logger.warning("model %s alias %s failed to load %s: %s", model, alias, version, exc)
        self.report()
        return self.registry.status()

    def report(self) -> None:
        status = self.registry.status()
        body = {
            "instance_id": self.instance_id,
            "slots": {
                alias: {
                    **status["slots"].get(alias, {
                        "version": None, "signature": None,
                        "generation": status["generations"].get(alias, 0),
                    }),
                    **({"generation": status["error_generations"][alias]}
                       if alias in status["error_generations"] else {}),
                }
                for alias in ALIASES
            },
            "errors": status["errors"],
        }
        try:
            self._client().post(
                f"{self.url}/api/v1/serving/{self.registry.model_name}/report",
                headers=self._headers(), json=body,
            ).raise_for_status()
        except Exception as exc:  # noqa: BLE001
            logger.warning("serving report failed: %s", exc)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    self.sync_once()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("serving sync failed: %s", exc)
                self._stop.wait(self.interval_s)

        self._thread = threading.Thread(target=loop, name=f"serving-sync-{self.registry.model_name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


def configure_from_env(
    model_name: str,
    loader: Callable[[Path], T],
    *,
    env_prefix: str = "MODEL_SERVING_",
) -> tuple[ServingRegistry[T] | None, ServingSync | None]:
    """Build the registry/sync pair from environment, or (None, None) if disabled.

    ``MODEL_SERVING_ENABLED``        true to serve orchestrator-managed packages
    ``MODEL_SERVING_ROOT``           writable directory for verified packages
    ``MODEL_SERVING_ORCHESTRATOR_URL`` training-orchestrator base URL
    ``MODEL_SERVING_API_KEY``        training-orchestrator service key
    ``MODEL_SERVING_TENANT``         tenant whose aliases this deployment serves
    ``MODEL_SERVING_SIGNING_KEY``    package signing key (TRAINING_ARTIFACT_SIGNING_KEY)
    ``MODEL_SERVING_INTERVAL_S``     poll interval (default 15)
    """
    env = os.environ
    if env.get(f"{env_prefix}ENABLED", "").strip().lower() not in ("1", "true", "yes", "on"):
        return None, None
    signing_key = env.get(f"{env_prefix}SIGNING_KEY") or env.get("TRAINING_ARTIFACT_SIGNING_KEY", "")
    if not signing_key:
        raise RuntimeError("Model serving requires a package signing key")
    registry: ServingRegistry[T] = ServingRegistry(
        model_name, loader, signing_key=signing_key,
        root=Path(env.get(f"{env_prefix}ROOT", "/var/lib/black-onyx/model-serving")) / model_name,
    )
    registry.restore()
    url = env.get(f"{env_prefix}ORCHESTRATOR_URL", "")
    if not url:
        return registry, None
    sync = ServingSync(
        registry,
        orchestrator_url=url,
        api_key=env.get(f"{env_prefix}API_KEY", ""),
        tenant_id=env.get(f"{env_prefix}TENANT", "default"),
        interval_s=float(env.get(f"{env_prefix}INTERVAL_S", "15")),
    )
    return registry, sync


def wait_until(predicate: Callable[[], bool], timeout_s: float, interval_s: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()
