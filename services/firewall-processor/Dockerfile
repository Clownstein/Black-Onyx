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
ENV FIREWALL_PROCESSOR_ENABLE_KAFKA=true

COPY packages/black_onyx_contracts /packages/black_onyx_contracts
COPY services/firewall-processor/pyproject.toml /app/pyproject.toml
COPY services/firewall-processor/firewall_processor /app/firewall_processor

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
ENV FIREWALL_PROCESSOR_ENABLE_KAFKA=true

USER app:app
EXPOSE 8099
CMD ["uvicorn", "firewall_processor.main:app", "--host", "0.0.0.0", "--port", "8099"]
