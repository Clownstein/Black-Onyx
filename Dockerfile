FROM node:22.17.0-bookworm-slim AS frontend
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
# Persist the npm download cache across rebuilds so lockfile-only changes do not
# re-fetch the whole tree on slow links.
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --no-audit --no-fund
COPY web/ ./
COPY BlackOnyxBackground.png /build/BlackOnyxBackground.png
COPY BlackOnyxTransparentLogo.png /build/BlackOnyxTransparentLogo.png
# Alias kept for docs/tools that still reference the historical filename.
COPY BlackOnyxBackground.png /build/background.png
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.8.3 AS uv

FROM python:3.12.11-slim-bookworm

# Install system dependencies
# - tesseract-ocr: kept as a fallback OCR backend (PaddleOCR is the default in Docker)
# - libgl1, libglib2.0-0: required by OpenCV / PaddleOCR
# - libgomp1: required by paddlepaddle (OpenMP runtime)
# - git: for pip installs from git
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libgl1 \
    libglib2.0-0 \
    libgomp1 \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ ./src/
COPY packages/black_onyx_contracts/ ./packages/black_onyx_contracts/

# Install the locked environment, including CUDA-enabled torch/torchvision
# (pytorch-cu126). The host NVIDIA driver + Docker --gpus (see compose) provide
# the GPU; the wheels ship the CUDA runtime libraries.
# llama-cpp-python compiles its native extension on platforms without a
# matching wheel. Keep the compiler toolchain in this build layer only and
# remove it before the runtime image is committed.
# --mount=type=cache keeps torch/paddle wheels on the Docker host between rebuilds.
# Pass --build-arg UV_OFFLINE=1 to force cache-only installs when the link is too
# slow for another multi-GB pull (requires a prior successful sync on this host).
ARG UV_OFFLINE=0
RUN --mount=type=cache,target=/root/.cache/uv \
    apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && if [ "$UV_OFFLINE" = "1" ]; then \
         uv sync --frozen --no-dev --offline \
           --extra image --extra ocr-paddle --extra llm --extra threat-intel; \
       else \
         uv sync --frozen --no-dev \
           --extra image --extra ocr-paddle --extra llm --extra threat-intel; \
       fi \
    && apt-get purge -y --auto-remove build-essential \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/app/.venv/bin:$PATH"

# Application assets change more frequently than Python dependencies, so copy
# them after the locked environment is built to preserve Docker layer caching.
COPY web/ ./web/
COPY --from=frontend /build/web/dist ./web/dist
COPY scripts/ ./scripts/
COPY config.example.yaml ./

# The runtime only needs ownership of its writable directories. Keeping code
# and the virtual environment root-owned avoids an expensive recursive chown.
RUN groupadd --system blackonyx && useradd --system --gid blackonyx --home /app blackonyx \
    && mkdir -p /app/data /app/.checkpoints /app/.cache \
    && chown blackonyx:blackonyx /app/data /app/.checkpoints /app/.cache
USER blackonyx

# Expose the web UI port
EXPOSE 8000

# Environment variables
# - Qdrant host points at the qdrant service in docker-compose
# - OCR backend defaults to PaddleOCR in Docker (override with QDRANT_OCR__BACKEND=tesseract to fall back)
ENV QDRANT_QDRANT__HOST=qdrant
ENV QDRANT_QDRANT__PORT=6333
ENV QDRANT_OCR__BACKEND=paddle
# PaddleOCR downloads model files to a cache dir on first run; keep it inside the image
ENV PADDLE_OCR_HOME=/app/.paddleocr
# Hugging Face / SentenceTransformers model caches must be writable by the
# non-root runtime user (home is /app, so the default ~/.cache fails otherwise).
ENV HF_HOME=/app/.cache/huggingface
ENV TRANSFORMERS_CACHE=/app/.cache/huggingface/transformers
ENV SENTENCE_TRANSFORMERS_HOME=/app/.cache/sentence-transformers
ENV TORCH_HOME=/app/.cache/torch
ENV XDG_CACHE_HOME=/app/.cache

# Default command runs the web UI. The same image is reused by docker-compose
# to run CLI subcommands (ingest, search, chat, collections, info, ...) by
# overriding the command/entrypoint, e.g.:
#   docker-compose run --rm cli ingest --directory /app/data
CMD ["black-onyx-web", "--host", "0.0.0.0", "--port", "8000"]
