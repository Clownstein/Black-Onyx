# Hardened multi-stage image pinned base (never :latest). Non-root uid 10001.
# Security gateway: receives BFF-proxied requests, dispatches to security-runner.
FROM python:3.12.14-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY packages/black_onyx_sandbox /packages/black_onyx_sandbox
COPY services/security-gateway /app

RUN pip install --no-cache-dir /packages/black_onyx_sandbox \
    && pip install --no-cache-dir .

FROM debian:sid-slim@sha256:ec3fa4e0b2987ae47be353f56854191e300261915470e40165b1c906d22a65db AS runtime
RUN rm -f /etc/apt/sources.list.d/* \
    && printf 'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] http://snapshot.debian.org/archive/debian/20260918T000000Z sid main\n' > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates libbz2-1.0 libexpat1 libffi8 liblzma5 libsqlite3-0 libssl3t64 libuuid1 zlib1g \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY deploy/detection/runtime/passwd /etc/passwd
COPY deploy/detection/runtime/group /etc/group
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

COPY --from=builder --chown=10001:10001 /usr/local /usr/local
COPY --from=builder /app/alembic /app/alembic
COPY --from=builder /app/alembic.ini /app/alembic.ini
RUN mkdir -p /app/state && chown 10001:10001 /app/state

USER 10001:10001
EXPOSE 8000
CMD ["/usr/local/bin/python", "-m", "security_gateway.startup"]
