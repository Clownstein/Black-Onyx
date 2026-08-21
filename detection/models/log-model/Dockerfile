# syntax=docker/dockerfile:1.7
# Hardened multi-stage image — pinned base (never :latest). Non-root uid 10001.
FROM python:3.12.11-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Prefer CPU wheels so local Compose builds do not pull multi-GB CUDA packages.
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu

COPY packages/black_onyx_contracts /packages/black_onyx_contracts
COPY packages/black_onyx_calibration /packages/black_onyx_calibration
COPY detection/models/common /models/common
COPY detection/models/log-model/pyproject.toml /app/pyproject.toml
COPY detection/models/log-model/log_model /app/log_model
COPY detection/models/log-model/inference /app/inference
COPY detection/models/log-model/artifacts /app/artifacts

# Shared BuildKit pip cache survives layer-cache misses and cancelled builds.
RUN --mount=type=cache,id=pip-anomaly-models,sharing=locked,target=/root/.cache/pip \
    pip install /packages/black_onyx_contracts \
    && pip install /packages/black_onyx_calibration \
    && pip install --extra-index-url "${TORCH_INDEX_URL}" .

ENV LOG_MODEL_ARTIFACTS_DIR=/app/artifacts

FROM python:3.12.11-slim AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=app:app /usr/local /usr/local
COPY --from=builder --chown=app:app /app /app
COPY --from=builder --chown=app:app /packages /packages
COPY --from=builder --chown=app:app /models /models
ENV LOG_MODEL_ARTIFACTS_DIR=/app/artifacts

USER app:app
EXPOSE 8090
CMD ["uvicorn", "inference.app:app", "--host", "0.0.0.0", "--port", "8090"]
