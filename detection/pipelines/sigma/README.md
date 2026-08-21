# Sigma-like offline matching

Curated YAML rules under `rules/` and a small Python runner that matches simple JSON events offline (no Kafka required).

## Layout

```text
pipelines/sigma/
  README.md
  run_sigma_match.py
  rules/
    proc_powershell_encoded.yml
    failed_logon_burst.yml
    rare_scheduled_task.yml
```

## Run

From repo root:

```powershell
python pipelines/sigma/run_sigma_match.py --events path\to\events.jsonl
python pipelines/sigma/run_sigma_match.py --events path\to\events.json --rules pipelines/sigma/rules
```

Events may be a JSON array, a single object, or JSONL (one event per line). Findings print as a JSON array on stdout.

## Event shape

Minimal fields used by the curated rules:

```json
{
  "event_id": "4688",
  "EventID": 4688,
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell -enc SQBFAFgA...",
  "Computer": "WORKSTATION01",
  "asset_id": "host-1",
  "tenant_id": "tenant-demo",
  "occurred_at": "2024-06-01T12:00:00Z"
}
```

Failed logon burst expects multiple events sharing `TargetUserName` / `asset_id` with `EventID` 4625 within a short window (handled by the runner’s burst aggregator).

## Adding rules

YAML keys:

| Key | Role |
| --- | --- |
| `title`, `id`, `level` | Metadata |
| `logsource` | Informational |
| `detection.selection` | Field equality / list membership |
| `detection.keywords` | Substring match on `CommandLine` / `Message` (case-insensitive) |
| `detection.condition` | `selection` (default) |
| `mitre_techniques` | ATT&CK technique IDs |
| `falsepositives` | Notes |

This is intentionally a **subset** of Sigma — enough for offline labs and CI smoke, not a full pySigma replacement.
