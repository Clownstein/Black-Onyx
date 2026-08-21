# syntax=docker/dockerfile:1.7
# Hardened multi-stage image — pinned base (never :latest). Non-root uid 10001.
FROM python:3.12.11-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY detection/models/host-state-model/pyproject.toml /app/pyproject.toml
COPY detection/models/host-state-model/host_state_model /app/host_state_model
COPY detection/models/host-state-model/inference /app/inference

RUN --mount=type=cache,id=pip-anomaly-models,sharing=locked,target=/root/.cache/pip \
    pip install .

FROM python:3.12.11-slim AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=app:app /usr/local /usr/local
COPY --from=builder --chown=app:app /app /app

USER app:app
EXPOSE 8104
CMD ["uvicorn", "inference.app:app", "--host", "0.0.0.0", "--port", "8104"]
