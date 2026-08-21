#!/usr/bin/env python3
"""Rewrite Python service/model Dockerfiles to hardened multi-stage non-root images."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYTHON_BASE = "python:3.12.11-slim"
SKIP = {
    "services/ingestion-gateway/Dockerfile",
    "frontend/Dockerfile",
    "services/malware-triage/Dockerfile",
}


def harden(path: Path) -> None:
    rel = path.relative_to(ROOT).as_posix()
    if rel in SKIP:
        print("skip", rel)
        return
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if not ln.startswith("FROM ")]
    body = "\n".join(lines).strip() + "\n"

    expose_m = re.search(r"^EXPOSE\s+(\d+)\s*$", body, re.M)
    cmd_m = re.search(r"^CMD\s+(.+)$", body, re.M)
    expose = expose_m.group(1) if expose_m else "8000"
    cmd = cmd_m.group(0) if cmd_m else 'CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8000"]'

    builder_lines = [
        ln
        for ln in body.splitlines()
        if not ln.startswith("EXPOSE ") and not ln.startswith("CMD ")
    ]
    builder_body = "\n".join(builder_lines).strip() + "\n"

    extra_copies = ""
    if re.search(r"COPY\s+\S+\s+/packages/", builder_body) or "/packages/" in builder_body:
        extra_copies += "COPY --from=builder --chown=app:app /packages /packages\n"
    if re.search(r"COPY\s+\S+\s+/models/", builder_body) or " /models/" in builder_body:
        extra_copies += "COPY --from=builder --chown=app:app /models /models\n"
    if "/opt/" in builder_body:
        extra_copies += "COPY --from=builder --chown=app:app /opt /opt\n"
    if "/playbooks" in builder_body:
        extra_copies += "COPY --from=builder --chown=app:app /playbooks /playbooks\n"

    runtime_envs = []
    for ln in builder_body.splitlines():
        if ln.startswith("ENV ") and "PYTHONDONTWRITEBYTECODE" not in ln and "PYTHONUNBUFFERED" not in ln:
            runtime_envs.append(ln)

    out = f"""# Hardened multi-stage image — pinned base (never :latest). Non-root uid 10001.
FROM {PYTHON_BASE} AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PIP_DISABLE_PIP_VERSION_CHECK=1 \\
    PIP_NO_CACHE_DIR=1

{builder_body}
FROM {PYTHON_BASE} AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 app \\
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=app:app /usr/local /usr/local
COPY --from=builder --chown=app:app /app /app
{extra_copies}{chr(10).join(runtime_envs)}

USER app:app
EXPOSE {expose}
{cmd}
"""
    path.write_text(out.rstrip() + "\n", encoding="utf-8", newline="\n")
    print("hardened", rel)


def main() -> None:
    for path in sorted(ROOT.rglob("Dockerfile")):
        if any(p in path.parts for p in (".venv", "node_modules", "dist")):
            continue
        harden(path)


if __name__ == "__main__":
    main()
