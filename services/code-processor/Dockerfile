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
ENV CODE_PROCESSOR_ENABLE_KAFKA=true

ARG CODEQL_VERSION=2.25.5
ARG CODEQL_LINUX_ZST_SHA256=76cd9d785940da0a5876676136be0c2803baa116304af5265052b74f1ec46258
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl zstd \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/codeql.tar.zst \
      "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.zst" \
    && echo "${CODEQL_LINUX_ZST_SHA256}  /tmp/codeql.tar.zst" | sha256sum -c - \
    && mkdir -p /opt/codeql \
    && tar --use-compress-program=unzstd -xf /tmp/codeql.tar.zst -C /opt/codeql --strip-components=1 \
    && rm /tmp/codeql.tar.zst

COPY services/code-processor/pyproject.toml /app/pyproject.toml
COPY services/code-processor/code_processor /app/code_processor
COPY detection/scanners/semgrep/rules /opt/black-onyx/scanners/semgrep/rules

RUN pip install --no-cache-dir .

FROM python:3.12.11-slim AS runtime
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

COPY --from=builder --chown=app:app /usr/local /usr/local
COPY --from=builder --chown=app:app /app /app
COPY --from=builder --chown=app:app /opt/codeql /opt/codeql
COPY --from=builder --chown=app:app /opt/black-onyx /opt/black-onyx
ENV CODE_PROCESSOR_ENABLE_KAFKA=true
ENV CODE_PROCESSOR_SEMGREP_RULES_DIR=/opt/black-onyx/scanners/semgrep/rules \
    CODE_PROCESSOR_CODEQL_CLI_PATH=/opt/codeql/codeql

USER app:app
EXPOSE 8093
CMD ["uvicorn", "code_processor.main:app", "--host", "0.0.0.0", "--port", "8093"]
