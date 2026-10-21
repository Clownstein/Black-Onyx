# Browser-acceptance runner: Playwright browsers + the Python app server in one
# image, so `scripts/e2e_server.py` stays reachable on 127.0.0.1:8765 exactly as
# it binds. Splitting them across two containers would require the server to
# bind 0.0.0.0 and widen QDRANT_SECURITY__ALLOWED_HOSTS, which is precisely the
# configuration the acceptance suite exists to check.
#
# Build from the repo root:
#   docker build -f deploy/e2e/Dockerfile -t black-onyx-e2e .
# Run (repo mounted so the suite reads the working tree, not a baked copy):
#   docker run --rm -v "$PWD:/work:ro" black-onyx-e2e
# Pass Playwright arguments through:
#   docker run --rm -v "$PWD:/work:ro" black-onyx-e2e --reporter=list auth.spec.ts
#
# The Playwright image tag must track web/package.json's @playwright/test
# version - the CLI refuses to drive browsers it was not built against.
FROM mcr.microsoft.com/playwright:v1.63.0-noble

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/opt/uv-cache

# python3-venv is separate from python3 on Ubuntu and uv needs it to seed one.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv python3-dev build-essential dos2unix \
 && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.8.3 /uv /usr/local/bin/uv

WORKDIR /app

# The acceptance suite covers authentication, RBAC and route delivery. Its
# server (scripts/e2e_server.py) stubs Qdrant out entirely and disables feeds
# and connectors, and the API application's import closure is FastAPI, pydantic,
# qdrant-client, the crypto/JWT stack and numpy - no torch, no transformers, no
# scipy. Installing them anyway cost ~24 GB of CUDA wheels that are never
# loaded. Anything wrongly excluded here surfaces as an ImportError when the
# server starts, not as a silently skipped test.
# Dependency manifests only, so the dependency layer survives source edits.
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
RUN uv venv /app/.venv \
 && VIRTUAL_ENV=/app/.venv uv sync --frozen --no-install-project --extra dev \
      --no-install-package torch \
      --no-install-package torchvision \
      --no-install-package triton \
      --no-install-package nvidia-cublas-cu12 \
      --no-install-package nvidia-cuda-cupti-cu12 \
      --no-install-package nvidia-cuda-nvrtc-cu12 \
      --no-install-package nvidia-cuda-runtime-cu12 \
      --no-install-package nvidia-cudnn-cu12 \
      --no-install-package nvidia-cufft-cu12 \
      --no-install-package nvidia-cufile-cu12 \
      --no-install-package nvidia-curand-cu12 \
      --no-install-package nvidia-cusolver-cu12 \
      --no-install-package nvidia-cusparse-cu12 \
      --no-install-package nvidia-cusparselt-cu12 \
      --no-install-package nvidia-nccl-cu12 \
      --no-install-package nvidia-nvjitlink-cu12 \
      --no-install-package nvidia-nvshmem-cu12 \
      --no-install-package nvidia-nvtx-cu12 \
      --no-install-package sentence-transformers \
      --no-install-package transformers \
      --no-install-package tokenizers \
      --no-install-package safetensors \
      --no-install-package huggingface-hub \
      --no-install-package hf-xet \
      --no-install-package open-clip-torch \
      --no-install-package timm \
      --no-install-package onnxruntime \
      --no-install-package sentencepiece \
      --no-install-package regex \
      --no-install-package ftfy \
      --no-install-package scipy \
      --no-install-package sympy \
      --no-install-package networkx \
      --no-install-package scikit-learn \
      --no-install-package scikit-image \
      --no-install-package paddleocr \
      --no-install-package paddlepaddle \
      --no-install-package pytesseract \
      --no-install-package imagehash \
      --no-install-package pymupdf \
      --no-install-package opencv-python \
      --no-install-package opencv-python-headless \
      --no-install-package opencv-contrib-python

COPY web/package.json web/package-lock.json ./web/
RUN cd web && npm ci

COPY . .
RUN VIRTUAL_ENV=/app/.venv uv sync --frozen --extra dev \
      --no-install-package torch \
      --no-install-package torchvision \
      --no-install-package triton \
      --no-install-package nvidia-cublas-cu12 \
      --no-install-package nvidia-cuda-cupti-cu12 \
      --no-install-package nvidia-cuda-nvrtc-cu12 \
      --no-install-package nvidia-cuda-runtime-cu12 \
      --no-install-package nvidia-cudnn-cu12 \
      --no-install-package nvidia-cufft-cu12 \
      --no-install-package nvidia-cufile-cu12 \
      --no-install-package nvidia-curand-cu12 \
      --no-install-package nvidia-cusolver-cu12 \
      --no-install-package nvidia-cusparse-cu12 \
      --no-install-package nvidia-cusparselt-cu12 \
      --no-install-package nvidia-nccl-cu12 \
      --no-install-package nvidia-nvjitlink-cu12 \
      --no-install-package nvidia-nvshmem-cu12 \
      --no-install-package nvidia-nvtx-cu12 \
      --no-install-package sentence-transformers \
      --no-install-package transformers \
      --no-install-package tokenizers \
      --no-install-package safetensors \
      --no-install-package huggingface-hub \
      --no-install-package hf-xet \
      --no-install-package open-clip-torch \
      --no-install-package timm \
      --no-install-package onnxruntime \
      --no-install-package sentencepiece \
      --no-install-package regex \
      --no-install-package ftfy \
      --no-install-package scipy \
      --no-install-package sympy \
      --no-install-package networkx \
      --no-install-package scikit-learn \
      --no-install-package scikit-image \
      --no-install-package paddleocr \
      --no-install-package paddlepaddle \
      --no-install-package pytesseract \
      --no-install-package imagehash \
      --no-install-package pymupdf \
      --no-install-package opencv-python \
      --no-install-package opencv-python-headless \
      --no-install-package opencv-contrib-python

# Playwright's config resolves the server interpreter at .venv/bin/python on
# Linux, which is what uv just created.
ENV PATH="/app/.venv/bin:${PATH}" \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Written inline rather than COPYed: .dockerignore excludes deploy/ from the
# build context, and that exclusion is right for the application image.
RUN cat > /tmp/entrypoint.sh <<'ENTRYPOINT'
#!/usr/bin/env bash
# Run the Playwright browser-acceptance suite against a freshly built frontend.
#
# With /work mounted the suite runs against the working tree: sources are copied
# into the image's tree so the baked node_modules and .venv are reused, since a
# bind-mounted Windows node_modules holds the wrong platform's binaries.
# Without /work it runs against the sources baked into the image.
set -euo pipefail

if [ -d /work ]; then
  echo "==> Syncing working tree from /work"
  for path in web/src web/e2e web/vite.config.ts web/tsconfig.json web/playwright.config.ts src scripts tests; do
    if [ -e "/work/${path}" ]; then
      rm -rf "/app/${path}"
      mkdir -p "$(dirname "/app/${path}")"
      cp -r "/work/${path}" "/app/${path}"
    fi
  done
fi

cd /app/web
echo "==> Building frontend"
npm run build
echo "==> Running Playwright acceptance suite"
exec npx playwright test "$@"
ENTRYPOINT

# The repo normalises to CRLF on a Windows checkout, so the heredoc above can
# land with carriage returns. A shebang ending in CR fails as `bash\r: not found`.
RUN dos2unix -q /tmp/entrypoint.sh \
 && install -m 0755 /tmp/entrypoint.sh /usr/local/bin/entrypoint.sh \
 && rm /tmp/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
