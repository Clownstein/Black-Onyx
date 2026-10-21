# Black Onyx tools: fine-tune dataset

Example conversations for teaching an LLM to call Black Onyx MCP tools correctly (including `confirm` gates and no SOAR auto-approve).

## Files

| File | Role |
| --- | --- |
| `tools.json` | OpenAI-style tool/function schemas for all **67** tools: 18 platform + 45 security executors + 4 approval/run controls |
| `generate_examples.py` | Regenerates `tools.json` (platform + `sec_*`) and the 85 platform examples |
| `generate_security_examples.py` | Appends 45 executor and 4 approval/run-control examples; run it **after** the line above |

## Format

Each `examples.jsonl` line:

```json
{
  "id": "evidence_search_01",
  "tool": "black_onyx_evidence_search",
  "tags": ["black_onyx_evidence_search"],
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_...", "type": "function", "function": {"name": "...", "arguments": "{...}"}}]},
    {"role": "tool", "tool_call_id": "call_...", "name": "...", "content": "{...}"},
    {"role": "assistant", "content": "Analyst-facing summary..."}
  ],
  "tools": [ /* full catalog from tools.json */ ]
}
```

Compatible with OpenAI chat fine-tuning / many OSS trainers that accept `messages` + `tool_calls`. Strip the `id` / `tool` / `tags` metadata keys if your trainer rejects unknown fields.

`examples_gemma.jsonl` uses Gemma 4 control tokens in assistant `content` strings (`<\|tool_call>…<tool_call|>`). Use with vLLM `--tool-call-parser gemma4` trainers or convert via `black_onyx.llm.tool_bridge.openai_tool_call_to_gemma`.

## Coverage

At least **one example per tool** (20 rows total: 18 primary + 2 extra safety/promote examples):

| Tool | Example id(s) |
| --- | --- |
| `black_onyx_evidence_search` | `evidence_search_01` |
| `black_onyx_ioc_enrich` | `ioc_enrich_01` |
| `black_onyx_case_assist` | `case_assist_01`, `case_assist_promote_01` |
| `black_onyx_rule_draft` | `rule_draft_01` |
| `black_onyx_attack_map` | `attack_map_01` |
| `black_onyx_hunt` | `hunt_01` |
| `black_onyx_incident_brief` | `incident_brief_01` |
| `black_onyx_asset_context` | `asset_context_01` |
| `black_onyx_response_draft` | `response_draft_01`, `response_draft_submit_01` |
| `black_onyx_ti_match` | `ti_match_01` |
| `black_onyx_watchlist_decay` | `watchlist_decay_01` |
| `black_onyx_misp_taxii_draft` | `misp_taxii_draft_01` |
| `black_onyx_connector_pulse` | `connector_pulse_01` |
| `black_onyx_feed_digest` | `feed_digest_01` |
| `black_onyx_model_ops` | `model_ops_01` |
| `passive_dns_whois` | `passive_dns_whois_01` |
| `url_screenshot_sandbox` | `url_screenshot_sandbox_01` |
| `certificate_transparency` | `certificate_transparency_01` |

## Safety behaviors encoded

- Mutations default to `confirm=false` drafts (`case_assist`, `misp_taxii_draft`, …).
- `response_draft` never approves; submit path stays pending / dry-run.
- Sandbox example shows soft-fail when lab flag is off.
- Non-read security executors receive only a single-use `approval_id` returned for an exact human-reviewed server preview; prose and tool-name lists never authorize execution.
- Paused security-agent examples cover status inspection and explicit approve/resume; denial uses the same resume control without an approval ID.

## In-repo trainer

Validate, export, or run a dry-run LoRA SFT (requires optional deps):

```powershell
cd black-onyx-tools
uv sync --extra dev
uv run black-onyx-tool-train validate
uv run black-onyx-tool-train export --format all
uv sync --extra train
uv run black-onyx-tool-train train --dry-run
```

Exports land in `datasets/tool_use/build/export/` (`train_openai.jsonl`, `train_hf.jsonl`, `train_gemma.jsonl`, `gemma_tool_declarations.txt`, …).

Gemma `<|tool>` declaration export only:

```powershell
uv run black-onyx-tool-train export --format gemma-declarations
```

## Regenerate

```powershell
cd black-onyx-tools
# Order matters: the first writes tools.json and the 85 platform examples,
# the second appends the 49 sec_* executor/control examples. Running only the second
# leaves the example files without platform rows.
python datasets/tool_use/generate_examples.py
python datasets/tool_use/generate_security_examples.py
uv run black-onyx-tool-train validate
```

## Notes

- Tool results are **synthetic** fixtures for training, not live TIP responses.
- Expand by cloning rows and varying IOC/host/incident IDs; keep tool names and argument shapes aligned with `tools.json`.
