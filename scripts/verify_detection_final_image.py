#!/usr/bin/env python3
"""Build, import-smoke, and socket-free scan one detection final image."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVICES = (
    "asset-registry", "code-enrichment-worker", "code-processor",
    "correlation-engine", "embedding-worker", "firewall-processor",
    "flow-processor", "host-state-processor", "ids-processor", "incident-api",
    "inference-worker", "integration-hub", "log-processor",
    "malware-orchestrator", "malware-processor", "malware-triage",
    "metrics-processor", "model-gateway", "notification-service",
    "profile-evaluator", "response-orchestrator", "smoke-consumer",
    "threat-intel-service", "training-orchestrator",
)
MODELS = ("host-state-model", "log-model", "metrics-model", "network-model")
ALL = SERVICES + MODELS


def run(*args: str) -> str:
    result = subprocess.run(
        args, cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True,
    )
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(args[:3])} failed ({result.returncode}):\n"
            f"{result.stdout[-4000:]}\n{result.stderr[-4000:]}"
        )
    return result.stdout.strip()


def verify(name: str, *, scan: bool) -> None:
    dockerfile = (
        Path("services") / name / "Dockerfile" if name in SERVICES
        else Path("detection/models") / name / "Dockerfile"
    )
    image = f"blackonyx-{name}:final-image-check"
    print(f"{name}: building", flush=True)
    run("docker", "build", "-f", str(dockerfile), "-t", image, ".")
    imports = "import sqlite3,ssl,pwd; assert pwd.getpwuid(10001).pw_name == 'app'"
    if name in {"embedding-worker", "log-model", "metrics-model", "network-model", "training-orchestrator"}:
        imports += "; import torch"
    if name == "embedding-worker":
        imports += "; import sentence_transformers"
    if name in {"log-model", "metrics-model", "network-model"}:
        imports += "; import onnxruntime"
    print(f"{name}: checking Python/native imports", flush=True)
    run(
        "docker", "run", "--rm", "--network", "none",
        "--entrypoint", "/usr/local/bin/python", image, "-c", imports,
    )
    if name == "code-processor":
        run(
            "docker", "run", "--rm", "--network", "none",
            "--entrypoint", "/opt/codeql/codeql", image, "version",
        )
        scc_version = run(
            "docker", "run", "--rm", "--network", "none",
            "--entrypoint", "/opt/codeql/tools/linux64/scc", image, "--version",
        )
        if scc_version != "scc version 4.0.0":
            raise RuntimeError(f"code-processor: unexpected CodeQL scc replacement: {scc_version}")
        fixture = Path(tempfile.mkdtemp(prefix=".codeql-image-fixture-", dir=ROOT)).resolve()
        if not fixture.is_relative_to(ROOT.resolve()) or fixture == ROOT.resolve():
            raise RuntimeError("Unsafe CodeQL fixture path")
        try:
            (fixture / "sample.py").write_text(
                "import subprocess\n\n"
                "def inspect(user_input):\n"
                "    return subprocess.run(user_input, shell=True)\n",
                encoding="utf-8",
            )
            fixture.chmod(0o755)
            (fixture / "sample.py").chmod(0o644)
            smoke = (
                "import json;from pathlib import Path;"
                "from code_processor.codeql_runner import run_codeql;"
                "findings,status=run_codeql(Path('/fixture'));"
                "assert status['status']=='ready' and 'python' in status['languages'],status;"
                "assert isinstance(findings,list);print(json.dumps(status))"
            )
            run(
                "docker", "run", "--rm", "--network", "none",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
                "-v", f"{fixture}:/fixture:ro",
                "-e", "CODE_PROCESSOR_CODEQL_ENABLED=true",
                "-e", "CODE_PROCESSOR_CODEQL_TIMEOUT_SECONDS=300",
                "-e", "CODE_PROCESSOR_CODEQL_RAM_MB=1024",
                "--entrypoint", "/usr/local/bin/python", image, "-c", smoke,
            )
        finally:
            shutil.rmtree(fixture)
    if name == "malware-triage":
        for binary, arguments in (
            ("/usr/bin/clamscan", ("--no-summary", "/etc/passwd")),
            ("/usr/bin/yara", ("--version",)),
            ("/usr/local/bin/capa", ("--version",)),
            ("/usr/local/bin/floss", ("--version",)),
        ):
            run(
                "docker", "run", "--rm", "--network", "none",
                "--entrypoint", binary, image, *arguments,
            )
    if not scan:
        print(f"{name}: build and imports passed (scan skipped)", flush=True)
        return

    temporary = Path(tempfile.mkdtemp(prefix=".final-image-check-", dir=ROOT)).resolve()
    if not temporary.is_relative_to(ROOT.resolve()) or temporary == ROOT.resolve():
        raise RuntimeError("Unsafe final-image scan directory")
    try:
        archive = temporary / "image.tar"
        print(f"{name}: scanning final image", flush=True)
        run("docker", "save", "-o", str(archive), image)
        output = run(
            "docker", "run", "--rm", "-v", f"{temporary}:/scan:ro",
            "-v", "blackonyx-trivy-cache:/root/.cache/trivy",
            "aquasec/trivy:0.69.3", "image", "--input", "/scan/image.tar",
            "--scanners", "vuln", "--severity", "HIGH,CRITICAL",
            "--exit-code", "0", "--timeout", "45m", "--no-progress", "--quiet",
            "--format", "json",
        )
        findings = [
            (result.get("Target", "?"), vulnerability.get("VulnerabilityID", "?"),
             vulnerability.get("PkgName", "?"), vulnerability.get("InstalledVersion", "?"))
            for result in json.loads(output).get("Results", [])
            for vulnerability in result.get("Vulnerabilities") or []
        ]
        if findings:
            raise RuntimeError(f"{name}: {len(findings)} HIGH/CRITICAL findings: {findings[:20]}")
        print(f"{name}: no HIGH/CRITICAL findings", flush=True)
    finally:
        shutil.rmtree(temporary)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", choices=ALL)
    parser.add_argument("--skip-scan", action="store_true")
    args = parser.parse_args()
    verify(args.name, scan=not args.skip_scan)


if __name__ == "__main__":
    main()
