"""Serving registry and replica sync for signed model packages."""
from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from black_onyx_model_package import build_model_package
from black_onyx_model_package.serving import (
    ServingRegistry,
    ServingSync,
    pack_package,
    package_signature,
    unpack_package,
)

KEY = "serving-test-key"


def _package(tmp_path: Path, version: str, name: str = "network-model") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    weight = tmp_path / f"w-{version}.onnx"
    weight.write_bytes(f"weights-{version}".encode())
    return build_model_package(
        tmp_path / f"out-{version}", model_name=name, version=version,
        dataset_manifest={"feature_schema": {"features": []}}, signing_key=KEY, model_source=weight,
        metrics={}, thresholds={}, config={"model_name": name}, calibration={},
    )


def _registry(tmp_path: Path, loaded: list[str] | None = None) -> ServingRegistry:
    def loader(path: Path) -> str:
        version = json.loads((path / "config.json").read_text())["model_version"]
        if loaded is not None:
            loaded.append(version)
        return f"model-{version}"

    return ServingRegistry("network-model", loader, signing_key=KEY, root=tmp_path / "serving")


def test_load_verify_and_swap(tmp_path):
    registry = _registry(tmp_path)
    one = _package(tmp_path, "1.0.0")
    registry.load_package("champion", "1.0.0", pack_package(one))
    assert registry.get("champion").model == "model-1.0.0"
    assert registry.get("canary").model == "model-1.0.0"  # falls back to champion
    two = _package(tmp_path, "1.0.1")
    registry.load_package("canary", "1.0.1", pack_package(two), expected_signature=package_signature(two))
    assert registry.get("canary").model == "model-1.0.1"
    assert registry.get("champion").model == "model-1.0.0"


def test_rejects_tampered_wrong_version_and_wrong_model(tmp_path):
    registry = _registry(tmp_path)
    package = _package(tmp_path, "1.0.0")
    with pytest.raises(ValueError, match="version"):
        registry.load_package("champion", "2.0.0", pack_package(package))
    with pytest.raises(ValueError, match="signature"):
        registry.load_package("champion", "1.0.0", pack_package(package), expected_signature="0" * 64)
    other = _package(tmp_path / "other", "1.0.0", name="metrics-model")
    with pytest.raises(ValueError, match="identity"):
        registry.load_package("champion", "1.0.0", pack_package(other))
    (package / "model.onnx").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="verification"):
        registry.load_package("champion", "1.0.0", pack_package(package))
    assert registry.get("champion") is None
    assert not list((tmp_path / "serving" / "packages").iterdir())


def test_unpack_refuses_traversal_and_links(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        data = b"x"
        info = tarfile.TarInfo("../escape.txt")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    with pytest.raises(ValueError):
        unpack_package(buffer.getvalue(), tmp_path / "out")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        link = tarfile.TarInfo("config.json")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)
    with pytest.raises(ValueError):
        unpack_package(buffer.getvalue(), tmp_path / "out2")


def test_restore_after_restart_reverifies(tmp_path):
    loaded: list[str] = []
    registry = _registry(tmp_path, loaded)
    registry.load_package("champion", "1.0.0", pack_package(_package(tmp_path, "1.0.0")))
    restarted = _registry(tmp_path, loaded)
    restarted.restore()
    assert restarted.get("champion").version == "1.0.0"
    assert loaded == ["1.0.0", "1.0.0"]


class FakeResponse:
    def __init__(self, payload=None, content=b"", status=200):
        self._payload, self.content, self.status_code = payload, content, status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeOrchestrator:
    def __init__(self, packages: dict[str, Path]):
        self.packages = packages
        self.desired: dict = {}
        self.reports: list[dict] = []

    def get(self, url, headers):
        assert headers["X-Tenant-Id"] == "tenant-a"
        if url.endswith("/desired"):
            return FakeResponse({"aliases": self.desired})
        version = url.split("/versions/")[1].split("/")[0]
        return FakeResponse(content=pack_package(self.packages[version]))

    def post(self, url, headers, json):
        self.reports.append(json)
        return FakeResponse()


def test_sync_converges_and_reports(tmp_path):
    one, two = _package(tmp_path, "1.0.0"), _package(tmp_path, "1.0.1")
    orchestrator = FakeOrchestrator({"1.0.0": one, "1.0.1": two})
    registry = _registry(tmp_path)
    sync = ServingSync(registry, orchestrator_url="http://orch", api_key="k", tenant_id="tenant-a",
                       instance_id="r1", http=orchestrator)
    orchestrator.desired = {"champion": {"version": "1.0.0", "signature": package_signature(one)}}
    sync.sync_once()
    assert orchestrator.reports[-1]["slots"]["champion"]["version"] == "1.0.0"
    orchestrator.desired = {"champion": {"version": "1.0.1", "signature": "f" * 64}}
    sync.sync_once()
    report = orchestrator.reports[-1]
    assert report["slots"]["champion"]["version"] == "1.0.0"  # kept serving the good package
    assert "1.0.1" in report["errors"]["champion"]
    orchestrator.desired = {"champion": {"version": "1.0.1", "signature": package_signature(two)}}
    sync.sync_once()
    assert orchestrator.reports[-1]["slots"]["champion"]["version"] == "1.0.1"
    assert orchestrator.reports[-1]["errors"] == {}


def test_sync_confirms_generation_fenced_removal(tmp_path):
    one = _package(tmp_path, "1.0.0")
    orchestrator = FakeOrchestrator({"1.0.0": one})
    registry = _registry(tmp_path)
    sync = ServingSync(
        registry, orchestrator_url="http://orch", api_key="k", tenant_id="tenant-a",
        instance_id="r1", http=orchestrator,
    )
    orchestrator.desired = {"champion": {
        "version": "1.0.0", "signature": package_signature(one), "generation": 1, "removed": False,
    }}
    sync.sync_once()
    assert registry.get("champion").generation == 1
    orchestrator.desired = {"champion": {
        "version": None, "signature": None, "generation": 2, "removed": True,
    }}
    sync.sync_once()
    report = orchestrator.reports[-1]["slots"]["champion"]
    assert registry.get("champion") is None
    assert report == {"version": None, "signature": None, "generation": 2}
    assert registry.status()["generations"]["champion"] == 2
