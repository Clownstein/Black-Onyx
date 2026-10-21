FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime-base

FROM node:26.10.0-bookworm-slim AS frontend
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
# Persist the npm download cache across rebuilds so lockfile-only changes do not
# re-fetch the whole tree on slow links.
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --no-audit --no-fund
COPY web/ ./
COPY BlackOnyxBackground.png /build/BlackOnyxBackground.png
COPY BlackOnyxTransparentLogo.png /build/BlackOnyxTransparentLogo.png
RUN npm run build


FROM ghcr.io/astral-sh/uv:0.12.22 AS uv


FROM python:3.12.14-slim-bookworm AS builder

# Install system dependencies
# - tesseract-ocr: default OCR backend; PaddleOCR remains an explicit optional extra
# - libgl1, libglib2.0-0: required by OpenCV / image processing
# - libgomp1: required by torch/OpenMP workloads
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
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY services/security-gateway/alembic/ ./services/security-gateway/alembic/
COPY services/security-gateway/alembic.ini ./services/security-gateway/alembic.ini
COPY packages/black_onyx_contracts/ ./packages/black_onyx_contracts/
# The `mcp` extra installs this from a local path, and mcp/registry.py reads
# datasets/tool_use/tools.json from it at runtime, so both must be present
# before uv sync. Without them load_tool_catalog() returns an empty list and
# the agent loop and MCP orchestrator run with no tools at all.
COPY black-onyx-tools/pyproject.toml black-onyx-tools/README.md ./black-onyx-tools/
COPY black-onyx-tools/src/ ./black-onyx-tools/src/
COPY black-onyx-tools/datasets/tool_use/tools.json ./black-onyx-tools/datasets/tool_use/tools.json

# Install the locked environment, including CUDA-enabled torch/torchvision
# (pytorch-cu126). The host NVIDIA driver + Docker --gpus (see compose) provide
# the GPU; the wheels ship the CUDA runtime libraries.
# Keep the compiler toolchain in this build layer only and remove it before the
# runtime image is committed. PaddleOCR remains an explicit opt-in; the
# production image uses the isolated llama server and Tesseract.
# CI leaves the uv cache on this layer's filesystem so the CUDA libraries can
# be hardlinked into the venv. A BuildKit cache mount is a different
# filesystem, which forces a full second copy and fills the runner disk.
# Local slow-link rebuilds opt into that mount with UV_CACHE_MOUNT=1, then
# UV_OFFLINE=1 reuses the wheels already stored there.
ARG UV_OFFLINE=0
ARG UV_CACHE_MOUNT=0
RUN --mount=type=cache,target=/opt/uv-cache \
    apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && if [ "$UV_CACHE_MOUNT" = "1" ]; then \
         mkdir -p /root/.cache && ln -sfn /opt/uv-cache /root/.cache/uv; \
       fi \
    && if [ "$UV_OFFLINE" = "1" ]; then \
         uv sync --frozen --no-dev --offline \
           --extra image --extra llm --extra threat-intel --extra mcp; \
       else \
         uv sync --frozen --no-dev \
           --extra image --extra llm --extra threat-intel --extra mcp; \
       fi \
    && if [ "$UV_CACHE_MOUNT" != "1" ]; then rm -rf /root/.cache/uv; fi \
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
RUN mkdir -p /app/data /app/.checkpoints /app/.cache /runtime-libs \
    && cp -L /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 /runtime-libs/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libffi.so.8 /runtime-libs/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libGL.so.1 /runtime-libs/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0 /runtime-libs/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libgomp.so.1 /runtime-libs/ \
    && for library in /usr/bin/tesseract \
      /usr/lib/x86_64-linux-gnu/libGL.so.1 \
      /usr/lib/x86_64-linux-gnu/libglib-2.0.so.0 \
      /usr/lib/x86_64-linux-gnu/libgomp.so.1; do \
         ldd "$library" | awk '$2 == "=>" && substr($3,1,1) == "/" {print $3}' \
           | while read -r dependency; do \
               case "$(basename "$dependency")" in \
                 libc.so.6|libm.so.6|libgcc_s.so.1|libstdc++.so.6) ;; \
                 *) cp -L "$dependency" "/runtime-libs/$(basename "$dependency")" ;; \
               esac; \
             done; \
       done


FROM debian:trixie-slim AS runtime-security
COPY --from=runtime-base /var/lib/dpkg/status.d/libssl3t64 /tmp/runtime-libssl-status
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade libssl3t64 \
    && fixed_version="$(dpkg-query -W -f='${Version}' libssl3t64)" \
    && sed -i "s/3.5.7-1~deb13u2/${fixed_version}/g" /tmp/runtime-libssl-status \
    && mkdir -p /runtime-security-libs \
    && cp -L /usr/lib/*/libssl.so.3 /usr/lib/*/libcrypto.so.3 /runtime-security-libs/ \
    && md5sum /usr/lib/x86_64-linux-gnu/libssl.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
       | sed 's#  /#  #' > /tmp/runtime-libssl.md5sums \
    && rm -rf /var/lib/apt/lists/*

# pg_dump/pg_restore for BackupManager on the distroless web/cli image.
# Debian's /usr/bin/pg_dump is a perl pg_wrapper symlink copy the real
# versioned binaries under /usr/lib/postgresql/*/bin instead.
FROM debian:bookworm-slim AS pg-tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client \
    && mkdir -p /pg-tools/bin /pg-tools/lib \
    && pg_bin="$(ls -1d /usr/lib/postgresql/*/bin | sort -V | tail -1)" \
    && test -n "$pg_bin" \
    && test -x "$pg_bin/pg_dump" && test -x "$pg_bin/pg_restore" \
    && cp -L "$pg_bin/pg_dump" "$pg_bin/pg_restore" /pg-tools/bin/ \
    && for binary in /pg-tools/bin/*; do \
         ldd "$binary" | awk '$2 == "=>" && substr($3,1,1) == "/" {print $3}' \
           | while read -r dependency; do \
               case "$(basename "$dependency")" in \
                 libc.so.6|libm.so.6|libgcc_s.so.1|libstdc++.so.6|libpthread.so.0|libdl.so.2|ld-linux-x86-64.so.2) ;; \
                 *) cp -L "$dependency" "/pg-tools/lib/$(basename "$dependency")" ;; \
               esac; \
             done; \
       done \
    && od -An -tx1 -N4 /pg-tools/bin/pg_dump | grep -q "7f 45 4c 46" \
    && od -An -tx1 -N4 /pg-tools/bin/pg_restore | grep -q "7f 45 4c 46" \
    && LD_LIBRARY_PATH=/pg-tools/lib /pg-tools/bin/pg_dump --version \
    && LD_LIBRARY_PATH=/pg-tools/lib /pg-tools/bin/pg_restore --version \
    && rm -rf /var/lib/apt/lists/*

FROM runtime-base AS runtime
WORKDIR /app
COPY deploy/detection/runtime/passwd /etc/passwd
COPY deploy/detection/runtime/group /etc/group
COPY --from=builder /usr/local /usr/local
COPY --from=builder /runtime-libs/ /usr/local/lib/
COPY --from=runtime-security /runtime-security-libs/ /usr/lib/x86_64-linux-gnu/
COPY --from=runtime-security /tmp/runtime-libssl-status /var/lib/dpkg/status.d/libssl3t64
COPY --from=runtime-security /tmp/runtime-libssl.md5sums /var/lib/dpkg/status.d/libssl3t64.md5sums
COPY --from=pg-tools /pg-tools/bin/ /usr/local/bin/
COPY --from=pg-tools /pg-tools/lib/ /usr/local/lib/
COPY --from=builder /usr/bin/tesseract /usr/bin/tesseract
COPY --from=builder /usr/share/tesseract-ocr /usr/share/tesseract-ocr
COPY --from=builder /app /app
COPY --from=gcr.io/distroless/cc-debian13:debug-nonroot@sha256:f525a9a37aed3e8a848f46cfe055999782d66ed797e9e2886928c8caaaa4fc52 /busybox/busybox /tmp/busybox
USER 0:0
RUN ["/tmp/busybox", "chown", "10001:10001", "/app/data", "/app/.checkpoints", "/app/.cache"]
RUN ["/tmp/busybox", "rm", "/tmp/busybox"]
ENV PATH=/app/.venv/bin:/usr/local/bin:/usr/bin:/bin \
    LD_LIBRARY_PATH=/usr/local/lib \
    HOME=/app
USER 10001:10001

# Expose the web UI port
EXPOSE 8000

# Environment variables
# - Qdrant host points at the qdrant service in docker-compose
# - OCR backend defaults to Tesseract; PaddleOCR is an explicit optional build
ENV QDRANT_QDRANT__HOST=qdrant
ENV QDRANT_QDRANT__PORT=6333
ENV QDRANT_OCR__BACKEND=tesseract
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
CMD ["/app/.venv/bin/python", "/app/scripts/start_black_onyx_web.py"]
