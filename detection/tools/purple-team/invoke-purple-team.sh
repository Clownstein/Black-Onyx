#!/usr/bin/env bash
# Optional bash twin of Invoke-PurpleTeam.ps1
#   bash detection/tools/purple-team/invoke-purple-team.sh --dry-run

set -euo pipefail

DRY_RUN=0
ATOMIC_PATH="${ATOMIC_RED_TEAM_PATH:-}"
FINDINGS_PATH=""
TENANT_ID=""
WINDOW_START=""
WINDOW_END=""
REPORT_PATH=""
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPECTED_MAP="${HERE}/expected_findings.json"
SCORER="${HERE}/score_purple_team.py"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run|-DryRun) DRY_RUN=1; shift ;;
    --atomic-path) ATOMIC_PATH="$2"; shift 2 ;;
    --expected-map) EXPECTED_MAP="$2"; shift 2 ;;
    --findings) FINDINGS_PATH="$2"; shift 2 ;;
    --tenant) TENANT_ID="$2"; shift 2 ;;
    --window-start) WINDOW_START="$2"; shift 2 ;;
    --window-end) WINDOW_END="$2"; shift 2 ;;
    --report) REPORT_PATH="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

score_requested=0
for value in "$FINDINGS_PATH" "$WINDOW_START" "$WINDOW_END" "$REPORT_PATH"; do
  if [[ -n "$value" ]]; then
    score_requested=1
  fi
done
if [[ "$score_requested" -eq 1 ]] && [[ -z "$FINDINGS_PATH" || -z "$WINDOW_START" || -z "$WINDOW_END" || -z "$REPORT_PATH" ]]; then
  echo "Scoring requires --findings, --window-start, --window-end, and --report." >&2
  exit 2
fi
if [[ "$DRY_RUN" -eq 1 && "$score_requested" -eq 1 ]]; then
  echo "--dry-run cannot be combined with scoring arguments." >&2
  exit 2
fi

if [[ ! -f "$EXPECTED_MAP" ]]; then
  echo "expected_findings.json not found at $EXPECTED_MAP" >&2
  exit 1
fi

echo "Purple-team expected findings map:"
python3 - <<'PY' "$EXPECTED_MAP"
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
for t in data["techniques"]:
    types = ", ".join(t["expected_finding_types"])
    print(f"  {t['technique_id']} ({t['name']}) -> {types}")
PY

echo
echo "Stack presence probes (container presence only - not health or SLO proof):"
for name in blackonyx-postgres blackonyx-redpanda blackonyx-ingestion-gateway blackonyx-incident-api; do
  if docker ps -q -f "name=${name}" | grep -q .; then
    echo "  OK   ${name}"
  else
    echo "  MISS ${name}"
  fi
done

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo
  echo "DryRun: skipping Atomic Red Team path gate."
  echo "OK - purple-team dry-run complete."
  exit 0
fi

if [[ "$score_requested" -eq 1 ]]; then
  args=("$SCORER" --expected-map "$EXPECTED_MAP" --findings "$FINDINGS_PATH" --window-start "$WINDOW_START" --window-end "$WINDOW_END" --report "$REPORT_PATH")
  [[ -n "$TENANT_ID" ]] && args+=(--tenant "$TENANT_ID")
  python3 "${args[@]}"
  exit $?
fi

if [[ -z "$ATOMIC_PATH" || ! -e "$ATOMIC_PATH" ]]; then
  cat >&2 <<'EOF'
Atomic Red Team path not found (ATOMIC_RED_TEAM_PATH / --atomic-path).
Install Atomic Red Team or Caldera outside this repo and re-run, or use --dry-run.
Fail-closed: refusing to claim a purple-team run without external tooling.
EOF
  exit 1
fi

echo
echo "Atomic path present: ${ATOMIC_PATH}"
echo "External Atomic path present; execution remains operator-owned."
echo "After the lab run, export findings and score with --findings --window-start --window-end --report."
