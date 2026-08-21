# Internal TLS for Compose mTLS (Phase 5).
#
# Generate material (not committed):
#   uv run python scripts/development/gen_internal_certs.py
#
# Enable:
#   docker compose ... -f docker-compose.mtls.yml up -d
#
# Plaintext lab escape hatch: omit mtls overlay / use docker-compose.plaintext-lab.yml notes in hardening.md.

generated/
