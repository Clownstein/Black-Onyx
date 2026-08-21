# Hardened multi-stage image — pinned base (never :latest). Non-root uid 10001.
FROM python:3.12.11-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY packages/black_onyx_contracts /packages/black_onyx_contracts
COPY packages/black_onyx_otel /packages/black_onyx_otel
COPY services/integration-hub/pyproject.toml /app/pyproject.toml
COPY services/integration-hub/integration_hub /app/integration_hub
COPY services/integration-hub/alembic /app/alembic
COPY services/integration-hub/alembic.ini /app/alembic.ini

RUN pip install --no-cache-dir /packages/black_onyx_contracts \
    && pip install --no-cache-dir /packages/black_onyx_otel \
    && pip install --no-cache-dir .

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
EXPOSE 8105
CMD ["uvicorn", "integration_hub.main:app", "--host", "0.0.0.0", "--port", "8105"]
