#!/usr/bin/env bash
# Verify SHA256SUMS and upload STIX bundle to threat-intel-service.
# Usage: ./import-ti-bundle.sh <bundle-dir> [THREAT_INTEL_BASE_URL]
set -euo pipefail

DIR="${1:?bundle directory required}"
BASE="${2:-http://localhost:8098}"
BUNDLE="$DIR/indicators-stix.json"
SUMS="$DIR/SHA256SUMS"

if [[ ! -f "$BUNDLE" || ! -f "$SUMS" ]]; then
  echo "Missing indicators-stix.json or SHA256SUMS in $DIR" >&2
  exit 1
fi

(
  cd "$DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
  else
    # macOS: verify first file entry manually
    expected=$(awk '{print $1}' SHA256SUMS | head -n1)
    actual=$(shasum -a 256 indicators-stix.json | awk '{print $1}')
    [[ "$expected" == "$actual" ]] || { echo "checksum mismatch" >&2; exit 1; }
  fi
)

echo "Uploading to ${BASE}/api/v1/indicators/upload-stix"
curl -fsS -X POST \
  -H "Content-Type: application/json" \
  --data-binary @"$BUNDLE" \
  "${BASE%/}/api/v1/indicators/upload-stix"

echo
echo "Import complete."
