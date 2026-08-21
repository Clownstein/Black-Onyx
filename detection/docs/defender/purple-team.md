# Purple-team validation harness

**Status: operator-scored harness present** — scaffolding under `detection/tools/purple-team/`
(`expected_findings.json`, `Invoke-PurpleTeam.ps1`, optional `.sh`). Atomic Red Team /
Caldera remain **external operator tools** (not shipped in this repo). Live scoring still
requires an external Atomic/Caldera install plus a lab endpoint. Dry-run only prints the
expected map and non-authoritative container-presence probes; after the lab exercise, an offline scorer
validates a time-bounded, single-tenant findings export and writes a JSON report. Do not
treat purple-team as runtime-proven detection coverage without a lab exercise.

Validate detectors and correlation with controlled adversary emulation — **Atomic Red Team**
and/or **MITRE Caldera** — against a lab that mirrors production collectors.

## Goals

- Confirm host-state / network / log rules fire for known techniques.
- Confirm multi-model kill-chain boosts when code + metrics + network co-occur.
- Produce evidence that TI enrichment and playbooks remain approval-gated.

## Harness

```powershell
powershell -File detection/tools/purple-team/Invoke-PurpleTeam.ps1 -DryRun
# Live gate (fail-closed without Atomic path):
# $env:ATOMIC_RED_TEAM_PATH = "C:\tools\atomic-red-team"
# powershell -File detection/tools/purple-team/Invoke-PurpleTeam.ps1
```

See `detection/tools/purple-team/README.md`.

After the operator-run exercise, score an exported findings capture (the scorer does not
call services or execute Atomic/Caldera):

```powershell
powershell -File detection/tools/purple-team/Invoke-PurpleTeam.ps1 `
  -FindingsPath .\purple-findings.json `
  -WindowStart "2026-08-11T12:00:00Z" `
  -WindowEnd "2026-08-11T12:30:00Z" `
  -ReportPath .\purple-report.json
```

## Procedure

1. **Baseline** — Stack healthy; empty or labeled lab tenant `tenant-purple`.
2. **Scope** — Pick ATT&CK techniques in `expected_findings.json` / `docs/defender/mitre-coverage.md`
   and visible on the ATT&amp;CK coverage UI (Navigator export supported).
3. **Execute** — Run Atomic tests (or Caldera abilities) on a **lab** endpoint only.
4. **Observe** — Ingest → processors → findings → correlation → incident-api.
5. **Score** — Pass if expected finding types / incident categories appear within SLO window.
6. **Cleanup** — Revert Atomic artifacts; mark incidents disposition `expected_change` or `benign_anomaly`.

## Safety

- Never run Atomic/Caldera against production without change control.
- Prefer dry-run response playbooks; do not auto-block from purple tests.
- Isolate lab `site_id` (see `docs/deployment/multi-site.md`).

## Optional OpenCanary

Deploy [OpenCanary](https://opencanary.readthedocs.io/) as a low-interaction honeypot on
the lab VLAN. Forward OpenCanary alerts into `logs.raw` or a dedicated webhook → gateway
so purple exercises can include decoy interaction without building a honeypot into the
core platform.
