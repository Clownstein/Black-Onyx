# MITRE ATT&CK coverage

| Layer | Implementation |
| --- | --- |
| Technique tags on findings/incidents | Schema fields `mitre_tactics`, `mitre_techniques`, `mitre_confidence` |
| Rule mapping | Detectors and host-state rules embed technique IDs |
| Coverage heatmap UI | ATT&CK page (incident merge + Navigator export) |
| Adversary emulation | Purple-team harness against operator Atomic Red Team / Caldera labs |
| Navigator export | JSON layer from the coverage API |

## Mapping sources

1. Deterministic detectors (`flow-processor`, `host-state-processor`, Sigma/Suricata).
2. TI indicators with `mitre_techniques`.
3. Optional offline LLM suggestions (never auto-execute).
4. Qdrant `attack_tech_v1` narrative similarity (seed via `scripts/development/restore_qdrant_attack_tech.py`) when vector search is enabled.
5. Security Profile filter on the ATT&CK coverage UI (`profileOnly`) for MITRE-oriented packs (e.g. `mitre-attack-core`).

Coverage is reported from the active detector and incident data. Deterministic
technique mappings and analyst-reviewed ATT&CK suggestions remain distinguishable
in the coverage view.
