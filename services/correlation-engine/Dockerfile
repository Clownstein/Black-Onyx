# Hardened multi-stage image pinned base (never :latest). Non-root uid 10001.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime-base

FROM python:3.12.14-slim AS builder
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
COPY services/correlation-engine /app

RUN pip install --no-cache-dir /packages/black_onyx_contracts \
    && pip install --no-cache-dir /packages/black_onyx_otel \
    && pip install --no-cache-dir .
RUN mkdir -p /runtime-libs \
    && cp /usr/lib/*/libsqlite3.so.0* /usr/lib/*/libffi.so.8* /runtime-libs/


COPY --from=runtime-base /var/lib/dpkg/status.d/libssl3t64 /tmp/runtime-libssl-status
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade libssl3t64 \
    && fixed_version="$(dpkg-query -W -f='${Version}' libssl3t64)" \
    && sed -i "s/3.5.7-1~deb13u2/${fixed_version}/g" /tmp/runtime-libssl-status \
    && mkdir -p /runtime-security-libs \
    && cp -L /usr/lib/*/libssl.so.3 /usr/lib/*/libcrypto.so.3 /runtime-security-libs/ \
    && md5sum /usr/lib/x86_64-linux-gnu/libssl.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
       | sed 's#  /#  #' > /tmp/runtime-libssl.md5sums \
    && rm -rf /var/lib/apt/lists/*
FROM runtime-base AS runtime
WORKDIR /app
COPY deploy/detection/runtime/passwd /etc/passwd
COPY deploy/detection/runtime/group /etc/group
ENV HOME=/tmp LD_LIBRARY_PATH=/usr/local/lib
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1


COPY --from=builder --chown=10001:10001 /usr/local /usr/local
COPY --from=builder --chown=10001:10001 /runtime-libs/ /usr/local/lib/
COPY --from=builder /runtime-security-libs/ /usr/lib/x86_64-linux-gnu/
COPY --from=builder /tmp/runtime-libssl-status /var/lib/dpkg/status.d/libssl3t64
COPY --from=builder /tmp/runtime-libssl.md5sums /var/lib/dpkg/status.d/libssl3t64.md5sums
COPY --from=builder --chown=10001:10001 /app /app
COPY --from=builder --chown=10001:10001 /packages /packages


USER 10001:10001
EXPOSE 8084
CMD ["/usr/local/bin/python", "-m", "uvicorn", "correlation_engine.main:app", "--host", "0.0.0.0", "--port", "8084"]
