# Purple-team harness

Lab-only adversary-emulation scaffolding for Black Onyx detection. This tree does
**not** ship Atomic Red Team or MITRE Caldera; it maps a few ATT&CK technique IDs
to expected finding types and reports non-authoritative container-presence probes before an
operator runs external tools against a lab endpoint.

## Prerequisites

- Detection stack healthy (platform + detection-core or detection-apps).
- External **Atomic Red Team** and/or **Caldera** installed outside this repo.
- Lab endpoint / tenant only — never production without change control.
- See `detection/docs/defender/purple-team.md`.

## Files

| File | Role |
| --- | --- |
| `expected_findings.json` | Technique ID → expected finding types |
| `Invoke-PurpleTeam.ps1` | Dry-run / health probes, Atomic path gate, and offline scorer wrapper |
| `invoke-purple-team.sh` | Optional bash twin |
| `score_purple_team.py` | Offline, time-bounded findings-export scorer |

## Dry-run (safe)

From repo root:

```powershell
powershell -File detection/tools/purple-team/Invoke-PurpleTeam.ps1 -DryRun
```

```bash
bash detection/tools/purple-team/invoke-purple-team.sh --dry-run
```

Dry-run prints the expected-findings map and checks container-presence probes.
Those probes are not service health or SLO evidence. Dry-run does **not** execute Atomic tests.

## Live gate (fail-closed)

Without `-DryRun`, the script requires `ATOMIC_RED_TEAM_PATH` (or `-AtomicPath`)
to point at an existing Atomic Red Team checkout. If missing, it exits non-zero
with a clear message. Actual Atomic invocation remains an operator step — this
harness does not claim detection proof by itself.

```powershell
$env:ATOMIC_RED_TEAM_PATH = "C:\tools\atomic-red-team"
powershell -File detection/tools/purple-team/Invoke-PurpleTeam.ps1
```

## Scoring

After running Atomic/Caldera on a lab host, export the matching `incident-api`
findings for the isolated tenant and score them locally. The capture must contain
only that tenant and each finding needs a timestamp (`occurred_at`, `timestamp`,
`created_at`, `observed_at`, or `window.start`). The scorer never contacts a
service or launches adversary tooling.

```powershell
powershell -File detection/tools/purple-team/Invoke-PurpleTeam.ps1 `
  -FindingsPath .\purple-findings.json `
  -WindowStart "2026-08-11T12:00:00Z" `
  -WindowEnd "2026-08-11T12:30:00Z" `
  -ReportPath .\purple-report.json
```

The report is machine-readable and exits non-zero when any technique has no
matching expected finding type. Disposition resulting lab incidents as
`expected_change` or `benign_anomaly` after scoring.
