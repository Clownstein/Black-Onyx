#!/usr/bin/env bash
# Generate an air-gap threat-intel STIX bundle + SHA256 manifest.
# Usage: ./generate-ti-bundle.sh [outdir]
set -euo pipefail

OUT="${1:-./ti-bundle-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"

BUNDLE="$OUT/indicators-stix.json"
cat >"$BUNDLE" <<'EOF'
{
  "type": "bundle",
  "id": "bundle--autoanalyzer-airgap-sample",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--airgap-sample-1",
      "spec_version": "2.1",
      "pattern": "[ipv4-addr:value = '198.51.100.66']",
      "pattern_type": "stix",
      "valid_from": "2024-01-01T00:00:00Z",
      "labels": ["airgap-sample"],
      "confidence": 80
    }
  ]
}
EOF

(
  cd "$OUT"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum indicators-stix.json > SHA256SUMS
  else
    shasum -a 256 indicators-stix.json | awk '{print $1"  "$2}' > SHA256SUMS
  fi
)

echo "Wrote $OUT (indicators-stix.json + SHA256SUMS)"
