# syntax=docker/dockerfile:1.7
# Hardened multi-stage image pinned base (never :latest). Non-root uid 10001.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime-base

FROM python:3.12.14-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Prefer CPU wheels so local Compose builds do not pull multi-GB CUDA packages.
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu

COPY packages/black_onyx_contracts /packages/black_onyx_contracts
COPY packages/black_onyx_calibration /packages/black_onyx_calibration
COPY packages/black_onyx_model_package /packages/black_onyx_model_package
COPY detection/models/common /models/common
COPY detection/models/log-model/pyproject.toml /app/pyproject.toml
COPY detection/models/log-model/log_model /app/log_model
COPY detection/models/log-model/inference /app/inference
COPY detection/models/log-model/artifacts /app/artifacts

# Shared BuildKit pip cache survives layer-cache misses and cancelled builds.
RUN --mount=type=cache,id=pip-black-onyx-models,sharing=locked,target=/root/.cache/pip \
    pip install /packages/black_onyx_contracts \
    && pip install /packages/black_onyx_calibration \
    && pip install /packages/black_onyx_model_package \
    && pip install --extra-index-url "${TORCH_INDEX_URL}" .

ENV LOG_MODEL_ARTIFACTS_DIR=/app/artifacts
RUN mkdir -p /runtime-libs \
    && cp /usr/lib/*/libsqlite3.so.0* /usr/lib/*/libffi.so.8* /runtime-libs/


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
FROM runtime-base AS runtime
WORKDIR /app
COPY deploy/detection/runtime/passwd /etc/passwd
COPY deploy/detection/runtime/group /etc/group
ENV HOME=/tmp LD_LIBRARY_PATH=/usr/local/lib
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1


COPY --from=builder --chown=10001:10001 /usr/local /usr/local
COPY --from=builder --chown=10001:10001 /runtime-libs/ /usr/local/lib/
COPY --from=builder /runtime-security-libs/ /usr/lib/x86_64-linux-gnu/
COPY --from=builder /tmp/runtime-libssl-status /var/lib/dpkg/status.d/libssl3t64
COPY --from=builder /tmp/runtime-libssl.md5sums /var/lib/dpkg/status.d/libssl3t64.md5sums
COPY --from=builder --chown=10001:10001 /app /app
COPY --from=builder --chown=10001:10001 /packages /packages
COPY --from=builder --chown=10001:10001 /models /models
ENV LOG_MODEL_ARTIFACTS_DIR=/app/artifacts

USER 10001:10001
EXPOSE 8090
CMD ["/usr/local/bin/python", "-m", "uvicorn", "inference.app:app", "--host", "0.0.0.0", "--port", "8090"]
