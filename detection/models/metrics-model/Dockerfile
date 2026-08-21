# syntax=docker/dockerfile:1.7
# Hardened multi-stage image — pinned base (never :latest). Non-root uid 10001.
FROM python:3.12.11-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu

COPY packages/black_onyx_calibration /packages/black_onyx_calibration
COPY detection/models/metrics-model/pyproject.toml /app/pyproject.toml
COPY detection/models/metrics-model/metrics_model /app/metrics_model
COPY detection/models/metrics-model/inference /app/inference
COPY detection/models/metrics-model/artifacts /app/artifacts

RUN --mount=type=cache,id=pip-anomaly-models,sharing=locked,target=/root/.cache/pip \
    pip install /packages/black_onyx_calibration \
    && pip install --extra-index-url "${TORCH_INDEX_URL}" .

FROM python:3.12.11-slim AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=app:app /usr/local /usr/local
COPY --from=builder --chown=app:app /app /app
COPY --from=builder --chown=app:app /packages /packages

USER app:app
EXPOSE 8102
CMD ["uvicorn", "inference.app:app", "--host", "0.0.0.0", "--port", "8102"]
