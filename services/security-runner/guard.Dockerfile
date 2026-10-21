# Trusted per-job firewall helper. Build only from a repository@sha256 base;
# publish the result and configure SECURITY_GUARD_IMAGE by its resulting digest.
ARG GUARD_BASE_IMAGE
FROM ${GUARD_BASE_IMAGE}
ARG GUARD_BASE_IMAGE
ARG DEBIAN_SNAPSHOT
ARG DEBIAN_SUITE

# Bootstrap the CA bundle from signed fixed-snapshot metadata; this base
# intentionally ships without ca-certificates.
RUN test -n "$DEBIAN_SNAPSHOT" \
    && test -n "$DEBIAN_SUITE" \
    && rm -f /etc/apt/sources.list.d/* \
    && printf 'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] http://snapshot.debian.org/archive/debian/%s %s main\n' "$DEBIAN_SNAPSHOT" "$DEBIAN_SUITE" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates coreutils nftables tcpdump \
    && rm -rf /var/lib/apt/lists/* \
    && command -v nft >/dev/null \
    && command -v tcpdump >/dev/null \
    && command -v timeout >/dev/null \
    && test "$(printf '%s' "$GUARD_BASE_IMAGE" | grep -Ec '^.+@sha256:[a-f0-9]{64}$')" = 1

ENTRYPOINT []
CMD ["/bin/sleep", "infinity"]
