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
ENV CODE_ENRICHMENT_ENABLE_KAFKA=true
ENV CODE_ENRICHMENT_PORT=8110

COPY services/code-enrichment-worker/pyproject.toml /app/pyproject.toml
COPY services/code-enrichment-worker/code_enrichment_worker /app/code_enrichment_worker
# Antares CLI source for `python -m antares_cli` (optional model loop via ANTARES_ENDPOINT)
COPY detection/models/antares-1b/assets/antares-cli/src /opt/antares-cli/src

ENV CODE_ENRICHMENT_ANTARES_CLI_SRC=/opt/antares-cli/src
ENV PYTHONPATH=/opt/antares-cli/src

RUN pip install --no-cache-dir .

FROM python:3.12.11-slim AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=app:app /usr/local /usr/local
COPY --from=builder --chown=app:app /app /app
COPY --from=builder --chown=app:app /opt /opt
ENV CODE_ENRICHMENT_ENABLE_KAFKA=true
ENV CODE_ENRICHMENT_PORT=8110
ENV CODE_ENRICHMENT_ANTARES_CLI_SRC=/opt/antares-cli/src
ENV PYTHONPATH=/opt/antares-cli/src

USER app:app
EXPOSE 8110
CMD ["uvicorn", "code_enrichment_worker.main:app", "--host", "0.0.0.0", "--port", "8110"]
