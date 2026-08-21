# Security Profiles (ops)

Evidence-oriented coverage against framework/industry packs. **Not** a legal certification. Design history: `docs_implemented/security_implementation.md`, `docs_implemented/security_standards.md`.

## Concepts

| Item | Path / API |
| --- | --- |
| Packs | `profiles/packs/{frameworks,industries,certification}/`, `profiles/surfaces/` |
| Presets | `profiles/presets.yaml` (returned with `GET /api/v1/security-packs`) |
| Bindings | `profiles/bindings/detector_map.yaml`, `scanner_map.yaml` |
| Semgrep packs | `scanners/semgrep/rules/profiles/` via `SEMGREP_PROFILE_CONFIGS` |
| API | incident-api `:8083` — `/api/v1/security-profiles*` |
| Continuous eval | profile-evaluator `:8116` (`PROFILE_EVALUATOR_ENABLE_LOOP=false` by default) |
| UI | `/security-profiles` |

## Operator workflow

1. `GET /api/v1/security-packs` — browse packs and presets.
2. `POST /api/v1/security-profiles` — create profile with `selected_packs`, surfaces, schedule.
3. `POST …/evaluate` — recompute coverage (persists check state for analysts).
4. `GET …/coverage` — inspect `pass` / `fail` / `unknown` / `attested` / `not_applicable`.
5. Attest or open exceptions for gaps; list via `GET …/exceptions`.
6. Export evidence: `POST …/certification-package?export_format=json|csv|zip` (disclaimer required). Auditor/viewer export does **not** persist evaluation side effects.

## Coverage rules (no silent pass)

| Automation | Missing evidence | Open finding tagged to check | Probe/telemetry OK finding |
| --- | --- | --- | --- |
| `manual` | `unknown` / awaiting attestation | `fail` | — |
| `auto` / `hybrid` | `unknown` / `telemetry_missing` | `fail` | `pass` / `telemetry_ok` |

Positive pass evidence types include finding types `probe_ok`, `compliance_ok`, `telemetry_ok`.

## Probes

profile-evaluator can hit `PROFILE_PROBE_URLS` for TLS/security-header checks and emit findings that flip webapp surface checks. On-demand: `POST /api/v1/profile-evaluator/evaluate`, `…/probe`.

## RBAC

- Create/patch/evaluate/attest: analyst+ (existing roles).
- `auditor` → viewer-equivalent (read + certification export without write side effects).
