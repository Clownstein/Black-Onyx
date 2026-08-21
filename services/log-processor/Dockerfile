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
COPY services/log-processor/pyproject.toml /app/pyproject.toml
COPY services/log-processor/log_processor /app/log_processor

RUN pip install --no-cache-dir /packages/black_onyx_contracts && pip install --no-cache-dir .

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
EXPOSE 8082
CMD ["uvicorn", "log_processor.main:app", "--host", "0.0.0.0", "--port", "8082"]
