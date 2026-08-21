# MITRE ATT&CK coverage

## Integrate vs build

| Layer | Approach |
| --- | --- |
| Technique tags on findings/incidents | **Build** — schema fields `mitre_tactics`, `mitre_techniques`, `mitre_confidence` |
| Rule mapping | **Build** — detectors and host-state rules embed technique IDs |
| Coverage heatmap UI | **Build** — frontend ATT&CK page (live incident merge + Navigator export) |
| Adversary emulation | **Integrate** — Atomic Red Team / Caldera (Phase 4) |
| Navigator export | **Build** — JSON layer export from coverage API |

## Mapping sources

1. Deterministic detectors (`flow-processor`, `host-state-processor`, Sigma/Suricata).
2. TI indicators with `mitre_techniques`.
3. Optional offline LLM suggestions (never auto-execute).
4. Qdrant `attack_tech_v1` narrative similarity (seed via `scripts/development/restore_qdrant_attack_tech.py`) when vector search is enabled.
5. Security Profile filter on the ATT&CK coverage UI (`profileOnly`) for MITRE-oriented packs (e.g. `mitre-attack-core`).

## Target

≥80% of deterministic detection rules carry at least one technique ID.
