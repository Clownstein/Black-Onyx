# Antares CLI Tools — Reuse Notes for AutoAnalyzer

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).


**Document version:** 1.0  
**Date:** July 27, 2026  
**Source:** `models/antares-1b/assets/antares-cli/`  
**Purpose:** Capture which Antares CLI building blocks are useful for AutoAnalyzer, and how to use them without putting Antares on the streaming inference path.

---

## Summary

The Antares CLI is most valuable as **reusable tooling and an async enrichment surface**, not as a fifth Kafka modality scorer.

| Use | Verdict |
|---|---|
| Async CWE → file localization (CI / analyst / high-risk code incidents) | **Yes** |
| Sandboxed read-only repo exploration (with or without Antares weights) | **Yes** |
| CWE taxonomy, `plan` selection, SARIF/JSON reports | **Yes** |
| Replace `code-model` / Semgrep on the hot path | **No** |
| Stream log / network / metrics scoring | **No** |

**Recommended placement:**

```text
PR/webhook → code-processor (fast risk + Semgrep)
                 ↓ high risk / known CWE
         antares tool query|sweep (async, sandboxed)
                 ↓ SARIF/JSON
         incident-api evidence / findings.code enrichment
```

---

## Location and licensing

| Item | Path / note |
|---|---|
| CLI package | `models/antares-1b/assets/antares-cli/` |
| Agent tools | `src/antares_cli/tools/` (`shell_exec.py`, `readonly_workspace.py`) |
| Automation commands | `src/antares_cli/commands/tool.py` |
| CWE helpers | `src/antares_cli/core/cwe.py`, `src/antares_cli/knowledge/` |
| CLI license | Apache License 2.0 |
| CWE data | MITRE CWE-derived; see `THIRD_PARTY_NOTICES.md` |

Requirements (from CLI README): Python 3.11+, `uv`, **Linux or macOS** (native Windows not supported), OpenAI-compatible `POST /v1/completions` endpoint for model runs, POSIX tools (`rg` / `tree` recommended).

---

## Reusable components

### 1. JSON automation surface (`antares tool`)

Non-interactive API for integrations:

```bash
printf '%s\n' '{"target":"./repo","cwe_ids":["CWE-89"],"tool_budget":20}' \
  | antares tool query --stdin

printf '%s\n' '{"target":"./repo","workers":4,"selection":{"scope":"owasp","cwe_level":"base","max_cwes":20}}' \
  | antares tool sweep --stdin
```

| Capability | Detail |
|---|---|
| Input | JSON object on stdin (max 1,000,000 chars) |
| Output | JSON on stdout; reports can also be JSON / Markdown / SARIF |
| Commands | `tool query` (explicit CWEs), `tool sweep` (multi-CWE) |
| Exit codes | `0` complete; `2` incomplete/operational failure (findings alone do not fail `tool`) |

**AutoAnalyzer fit:** CI jobs, webhook workers, or a small enrichment service that only runs after a high-risk code finding.

### 2. Read-only sandbox

| Module | Role |
|---|---|
| `tools/readonly_workspace.py` | Immutable repo snapshot: copy, strip write bits, sanitize symlinks, exclude secrets/junk dirs |
| `tools/shell_exec.py` | Allowlisted inspection commands only (`cat`, `find`, `grep`, `rg`, `ls`, `head`, `sed`, …); no redirects, no network clients, bounded output |

Also relevant:

- Sensitive-path policy (`core/sensitive_paths.py`): `.env*`, key material, `.ssh` / `.aws` / `.kube`, etc., unless explicitly `--allow-sensitive-file`
- Snapshot limits: 100,000 files, 2 GiB total, 256 MiB per file

**AutoAnalyzer fit:** Safety layer for *any* future agentic or exploratory code scan — valuable even if Antares weights are never hosted.

### 3. CWE taxonomy and `antares plan` (no model)

| Capability | Detail |
|---|---|
| Bundled taxonomy | MITRE CWE 4.20 (~969 weaknesses) |
| Scopes | `auto`, `top25`, `owasp` |
| Levels | `pillar`, `class`, `base`, `variant`, `compound` |
| `antares plan PATH` | Local profiling + CWE selection **without** calling inference |
| Normalization | `core/cwe.py` → canonical `CWE-NNN` |

**AutoAnalyzer fit:**

- Map Semgrep/heuristic hits to canonical CWE IDs on findings
- Feed MITRE-oriented triage in the UI / correlation metadata
- Choose which CWEs to send to a later Antares (or other) investigation

### 4. Finding and report contracts

Findings are **file-level** (not line-level remediation):

- CWE IDs, optional submission rank, report summary
- Default reports: `report.json`, `report.md`, `report.sarif`
- Deduplication by path + CWE scope

**AutoAnalyzer fit:** Attach SARIF/JSON as incident evidence; keep human review required (CLI itself frames results as leads, not proof).

### 5. Run history and traces

Local provenance under `~/.local/share/antares-cli` (or `ANTARES_DATA_DIR`):

- `antares runs list|show|trace|export`
- Private traces may contain prompts, tool I/O, and source excerpts
- Portable exports redact many sensitive fields but still retain paths/metadata — review before sharing

**AutoAnalyzer fit:** Audit trail if agentic scans become part of IR / CI.

---

## What not to reuse as a streaming model

| Concern | Implication |
|---|---|
| Agentic multi-turn loop (≤15–50 tool calls) | Latency and cost wrong for Kafka feature windows |
| Decoder LLM (350M/1B) | Needs GPU-class serving (vLLM + completions API), not ONNX CPU hot path |
| Completions-only contract | Not interchangeable with chat or `/v1/predict` model-gateway |
| Repo content sent to endpoint | Tenancy, retention, and data-handling policy required |
| No native Windows | Run via Linux containers on Windows SOC hosts |

Keep Antares (and this CLI’s model path) on **async / CI / analyst-triggered** enrichment only. Streaming code risk stays with `code-processor` + `code-model` (and DistilBERT/CodeReviewer-class upgrades from `suggested_models.md`).

---

## Suggested integration shape

```text
1. code-processor emits advisory finding (Semgrep / heuristics / risk score)
2. If severity/CWE warrants enrichment:
     - materialize authorized repo snapshot (or clone at commit)
     - optionally: antares plan → selected CWEs
     - antares tool query|sweep --stdin → JSON/SARIF
3. Map file+CWE results into:
     - findings.code evidence_refs / contributors, and/or
     - incident comments / attachments
4. Analyst verifies before any remediation (platform non-goal: autonomous code rejection)
```

**Highest leverage without hosting weights:** adopt sandbox + sensitive-path + CWE normalize/`plan` patterns (design reference or Apache-2.0 vendoring, with MITRE notices for CWE data).

**Highest leverage with weights:** wrap `antares tool query` behind a worker that only runs when findings already carry a CWE (or after `plan`).

---

## Related docs

- Antares model card / limitations: `models/antares-1b/README.md`
- Platform model shortlist: `suggested_models.md` (Antares = offline triage only)
- Broader defender roadmap: `planned_upgrades.md` (code/TI/SOAR phases)

---

## Bottom line

Use Antares CLI for **sandboxed, automatable, CWE-aware code investigation** and for **policies/contracts** (readonly exec, secrets exclusion, CWE/SARIF). Do not wire it into the continuous log/network/metrics/code scoring spine.
