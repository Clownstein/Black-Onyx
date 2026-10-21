# Hardened multi-stage image pinned base (never :latest). Non-root uid 10001.
# Security runner: Docker-owning authenticated execution backend.
# Mounts the Docker socket for ephemeral container creation; in production,
# replace with docker-socket-proxy granting only CONTAINERS+EXEC+POST+LOGS.
FROM python:3.12.14-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY services/security-runner /app

RUN pip install --no-cache-dir .

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
COPY scripts/fix_security_sessions_owner.py /usr/local/lib/black-onyx/fix_security_sessions_owner.py

USER 10001:10001
EXPOSE 8080
CMD ["/usr/local/bin/python", "-m", "uvicorn", "security_runner.app:app", "--host", "0.0.0.0", "--port", "8080"]
