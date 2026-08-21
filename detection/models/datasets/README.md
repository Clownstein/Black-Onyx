# Model dataset formats

These examples mirror the feature records produced by Black Onyx processors and consumed by model inference. They contain only fictional tenants, assets, hashes, repositories, and code. They are deliberately synthetic, but the detailed rows preserve runtime windowing, processor provenance, timestamps, hashed identities, detector evidence, scanner metadata, and review annotations rather than reducing a record to a label.

## Trainable streaming models

Training files are UTF-8 JSON Lines: one complete JSON object per line. `label` is the supervised target (`0` normal/low risk, `1` anomalous/high risk); `split` is one of `train`, `validation`, or `test`. Identifiers and time windows are retained for provenance but must not be used as learned features.

| Model | Example | Native platform record | Required model fields |
| --- | --- | --- | --- |
| log-model | `log-model/training/examples/platform_sequences.jsonl` | `logs.features` | non-empty `events`, each with `template_id` and `severity` |
| network-model | `network-model/training/examples/platform_windows.jsonl` | `network.features` | non-empty `flows`; hashed peers only; no raw IP addresses |
| metrics-model | `metrics-model/training/examples/platform_windows.jsonl` | `metrics.features` | all seven `web_service_v1` metric series plus matching missingness |
| code-model | `code-model/training/examples/platform_changes.jsonl` | `code.features` | `diff_text`, `files_changed`, `diff_stats`, and `scanner_findings` |

Each streaming example contains balanced normal/risk cases across `train`, `validation`, and `test`, including detailed processor-shaped records. Use the model's `training/train.py --dataset <path>` option. Real training sets must contain both labels, keep train/validation/test groups separated by asset/repository and time, and be reviewed for secrets, personal data, licensing, and label provenance.

Production metric windows contain 60 resampled points. The compact example uses eight points and is padded by the same `window_to_tensor` function used at inference. Network rows are padded to 256 flows and transformed into the current 20-channel feature layout. Log template IDs must come from the deployed Drain3/template-extraction configuration.

## Non-training model surfaces

- `host-state-model/examples/platform_requests.jsonl` contains complete pass-through inference requests. Host-state has no learned weights; upstream rule scores are the authoritative inputs.
- `malware-static/training/examples/manifest.example.csv` defines the external PE corpus manifest. Binary samples are deliberately not committed. `relative_path` resolves under an operator-supplied corpus root and `label` is `0` benign or `1` malware.
- `antares-1b/examples/platform_localization_tasks.jsonl` is the task manifest used for offline localization evaluation. Black Onyx does not retrain Antares; repository snapshots and ground-truth files remain external and access-controlled.

Never place raw credentials, unredacted customer logs, raw network addresses, proprietary repositories, or malware binaries in this repository.
