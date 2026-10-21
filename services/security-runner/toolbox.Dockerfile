# Untrusted tool executors. No package installation occurs at job runtime.
# Pin both the base and final published image by digest.
ARG TOOLBOX_BASE_IMAGE
FROM ${TOOLBOX_BASE_IMAGE}
ARG TOOLBOX_BASE_IMAGE
ARG DEBIAN_SNAPSHOT
ARG DEBIAN_SUITE
ARG GOBUSTER_DEBIAN_VERSION
ARG FOUNDRY_VERSION
ARG FOUNDRY_SHA256
ARG SOLC_DOWNLOAD_URL
ARG SOLC_SHA256
ARG NIKTO_VERSION
ARG NIKTO_SHA256
ARG FILEBYTES_VERSION
ARG FILEBYTES_SHA256

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/blackonyx/bin:/usr/local/bin:/usr/bin:/bin

# The minimal pinned base has no CA bundle yet. APT authenticates this fixed
# snapshot with Debian's archive keyring; direct downloads below use HTTPS and
# independently reviewed SHA-256 hashes.
RUN test -n "$DEBIAN_SNAPSHOT" \
    && test -n "$DEBIAN_SUITE" \
    && rm -f /etc/apt/sources.list.d/* \
    && printf 'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] http://snapshot.debian.org/archive/debian/%s %s main\n' "$DEBIAN_SNAPSHOT" "$DEBIAN_SUITE" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       binutils ca-certificates checksec curl file gcc git gobuster=${GOBUSTER_DEBIAN_VERSION} hydra libradare2-6.0.0t64 libnet-ssleay-perl libxml-writer-perl nmap passwd perl python3 python3-dev python3-pip \
       python3-venv radare2 sqlmap tshark whois yara \
    && rm -rf /var/lib/apt/lists/* \
    && test "$(printf '%s' "$TOOLBOX_BASE_IMAGE" | grep -Ec '^.+@sha256:[a-f0-9]{64}$')" = 1

# Build-time downloads are versioned and checksum-verified. These values are
# mandatory inputs from the reviewed image-build lock; nothing is downloaded
# by an executing tool job.
RUN set -eu \
    && test -n "$FOUNDRY_VERSION" && test "$(printf '%s' "$FOUNDRY_SHA256" | grep -Ec '^[a-f0-9]{64}$')" = 1 \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
       "https://github.com/foundry-rs/foundry/releases/download/v${FOUNDRY_VERSION}/foundry_v${FOUNDRY_VERSION}_linux_amd64.tar.gz" -o /tmp/foundry.tar.gz \
    && echo "$FOUNDRY_SHA256  /tmp/foundry.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/foundry.tar.gz -C /usr/local/bin cast forge anvil \
    && rm /tmp/foundry.tar.gz \
    && test -n "$SOLC_DOWNLOAD_URL" && test "$(printf '%s' "$SOLC_SHA256" | grep -Ec '^[a-f0-9]{64}$')" = 1 \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$SOLC_DOWNLOAD_URL" -o /usr/local/bin/solc \
    && echo "$SOLC_SHA256  /usr/local/bin/solc" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/solc

RUN set -eu \
    && test -n "$NIKTO_VERSION" && test "$(printf '%s' "$NIKTO_SHA256" | grep -Ec '^[a-f0-9]{64}$')" = 1 \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
       "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz" -o /tmp/nikto.tar.gz \
    && echo "$NIKTO_SHA256  /tmp/nikto.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/nikto \
    && tar -xzf /tmp/nikto.tar.gz --strip-components=1 -C /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod 0755 /opt/nikto/program/nikto.pl \
    && rm /tmp/nikto.tar.gz

COPY services/security-runner/toolbox-requirements.txt /tmp/toolbox-requirements.txt
RUN python3 -m venv /opt/blackonyx \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
       "https://files.pythonhosted.org/packages/01/44/4ea92a74ca7d7940a29d6c437f62a91fd05d43bfa04fc8306b5dc541d01d/filebytes-${FILEBYTES_VERSION}.tar.gz" -o /tmp/filebytes.tar.gz \
    && echo "$FILEBYTES_SHA256  /tmp/filebytes.tar.gz" | sha256sum -c - \
    && mkdir /tmp/filebytes && tar -xzf /tmp/filebytes.tar.gz --strip-components=1 -C /tmp/filebytes \
    && sed -i 's/isinstance(e.value, ast.Str)/isinstance(e.value, ast.Constant)/; s/e.value.s/e.value.value/' /tmp/filebytes/setup.py \
    && /opt/blackonyx/bin/pip install --no-cache-dir /tmp/filebytes \
    && /opt/blackonyx/bin/pip install --no-cache-dir -r /tmp/toolbox-requirements.txt \
    && rm -rf /tmp/filebytes /tmp/filebytes.tar.gz /tmp/toolbox-requirements.txt

COPY services/security-runner/toolbox/ /usr/share/blackonyx/
RUN chmod -R a-w /usr/share/blackonyx \
    && chmod 0755 /usr/bin/gobuster /usr/local/bin/cast /usr/local/bin/forge /usr/local/bin/anvil /usr/local/bin/solc \
    && test "$(wc -l < /usr/share/blackonyx/wordlists/common.txt)" -le 5000 \
    && test "$(wc -l < /usr/share/blackonyx/wordlists/usernames.txt)" -le 20 \
    && test "$(wc -l < /usr/share/blackonyx/wordlists/passwords.txt)" -le 200 \
    && printf 'toolbox:x:10001:\n' >> /etc/group \
    && printf 'toolbox:x:10001:10001:Black Onyx toolbox:/home/toolbox:/usr/sbin/nologin\n' >> /etc/passwd \
    && mkdir -p /home/toolbox \
    && chown -R 10001:10001 /home/toolbox

USER 10001:10001
WORKDIR /workspace
ENTRYPOINT []
