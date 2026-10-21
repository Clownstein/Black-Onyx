# Hardened multi-stage image pinned base (never :latest). Non-root uid 10001.
FROM gcr.io/distroless/cc-debian13:debug-nonroot@sha256:984d31d4bd6e71bb9469353d93e73c68f7b3c17142b2aec45f2a960489095b22 AS runtime-base

FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS scc-builder
WORKDIR /build
RUN mkdir -p /out \
    && go mod init blackonyx-scc-build \
    && go get github.com/boyter/scc/v4@v4.0.0 \
    && go get golang.org/x/crypto@v0.55.0 \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/scc github.com/boyter/scc/v4


FROM python:3.12.14-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CODE_PROCESSOR_ENABLE_KAFKA=true

ARG CODEQL_VERSION=2.27.1
ARG CODEQL_LINUX_ZST_SHA256=1ec99cfa9420f04c2330784b4ddb8363a0dd67c3e4471cd93963c50e6c433717
ARG JACKSON_VERSION=2.18.11
ARG JACKSON_CORE_SHA256=825fa72dfb9e2f8a642322f1390dbac22c30d15ebd6dc6b3772158821ee124eb
ARG JACKSON_DATABIND_SHA256=075ad94a76c3edf83e1972dc26f476361eb6b9d0e260d93fc11105509bc79cab
ARG JACKSON_ANNOTATIONS_SHA256=9eab0d36da981645392427eedcb087e13be542488e37f935723dc0be50d18a53
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl zstd \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/codeql.tar.zst \
      "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.zst" \
    && echo "${CODEQL_LINUX_ZST_SHA256}  /tmp/codeql.tar.zst" | sha256sum -c - \
    && mkdir -p /opt/codeql \
    && tar --use-compress-program=unzstd -xf /tmp/codeql.tar.zst -C /opt/codeql --strip-components=1 \
    && rm /tmp/codeql.tar.zst \
    && for artifact in jackson-core jackson-databind jackson-annotations; do \
      case "$artifact" in \
        jackson-core) checksum="$JACKSON_CORE_SHA256" ;; \
        jackson-databind) checksum="$JACKSON_DATABIND_SHA256" ;; \
        jackson-annotations) checksum="$JACKSON_ANNOTATIONS_SHA256" ;; \
      esac; \
      url="https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/$artifact/$JACKSON_VERSION/$artifact-$JACKSON_VERSION.jar"; \
      mkdir -p /opt/jackson-fixed; \
      curl -fsSL "$url" -o "/opt/jackson-fixed/$artifact.jar"; \
      echo "$checksum  /opt/jackson-fixed/$artifact.jar" | sha256sum -c -; \
      old_path="/opt/codeql/java/tools/com/fasterxml/jackson/core/$artifact/2.18.6/$artifact-2.18.6.jar"; \
      test -f "$old_path"; \
      cp "/opt/jackson-fixed/$artifact.jar" "$old_path"; \
    done

# CodeQL's own fat jars (codeql.jar, extractors, the gradle dependency-graph plugin) embed older
# Jackson builds with known CVEs. Overwrite those classes and the embedded pom metadata in place.
COPY services/code-processor/patch_jackson.py /tmp/patch_jackson.py
# The Gradle dependency-graph helper shades a *relocated* Jackson 2.18.8 that cannot be swapped in
# place. code-processor never runs Gradle builds or submits dependency graphs, so drop it; the
# patch script then fails the build if any other relocated copy remains.
RUN rm -rf /opt/codeql/java/tools/depgraph-plugin-maven-repo \
    && JACKSON_FAIL_ON_RELOCATED=1 python /tmp/patch_jackson.py /opt/codeql \
      /opt/jackson-fixed/jackson-core.jar \
      /opt/jackson-fixed/jackson-databind.jar \
      /opt/jackson-fixed/jackson-annotations.jar \
    && rm -rf /opt/jackson-fixed /tmp/patch_jackson.py

COPY services/code-processor/pyproject.toml /app/pyproject.toml
COPY services/code-processor/code_processor /app/code_processor
COPY detection/scanners/semgrep/rules /opt/black-onyx/scanners/semgrep/rules

RUN pip install --no-cache-dir .
# semgrep 1.178.0 pins pyjwt~=2.13.0, which has HIGH/CRITICAL CVEs; override past the pin.
# Drop this once semgrep relaxes the pin.
ARG PYJWT_VERSION=2.15.1
RUN pip install --no-cache-dir "pyjwt[crypto]==${PYJWT_VERSION}"

RUN mkdir -p /runtime-libs \
    && cp /usr/lib/*/libsqlite3.so.0* /usr/lib/*/libffi.so.8* /lib/*/libtinfo.so.6* /runtime-libs/


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
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    LD_LIBRARY_PATH=/usr/local/lib \
    PATH=/busybox:/usr/local/bin:/usr/bin:/bin

COPY --from=builder --chown=10001:10001 /usr/local /usr/local
COPY --from=builder --chown=10001:10001 /runtime-libs/ /usr/local/lib/
COPY --from=builder /runtime-security-libs/ /usr/lib/x86_64-linux-gnu/
COPY --from=builder /tmp/runtime-libssl-status /var/lib/dpkg/status.d/libssl3t64
COPY --from=builder /tmp/runtime-libssl.md5sums /var/lib/dpkg/status.d/libssl3t64.md5sums
COPY --from=builder --chown=10001:10001 /app /app
COPY --from=builder --chown=10001:10001 /opt/codeql /opt/codeql
COPY --from=scc-builder --chown=10001:10001 /out/scc /opt/codeql/tools/linux64/scc
COPY --from=builder --chown=10001:10001 /opt/black-onyx /opt/black-onyx
COPY --from=builder /bin/bash /bin/bash
COPY --from=builder /usr/bin/env /usr/bin/env
COPY --from=runtime-base /busybox/busybox /bin/sh
ENV CODE_PROCESSOR_ENABLE_KAFKA=true
ENV CODE_PROCESSOR_SEMGREP_RULES_DIR=/opt/black-onyx/scanners/semgrep/rules \
    CODE_PROCESSOR_CODEQL_CLI_PATH=/opt/codeql/codeql

USER 10001:10001
EXPOSE 8093
CMD ["/usr/local/bin/python", "-m", "uvicorn", "code_processor.main:app", "--host", "0.0.0.0", "--port", "8093"]
