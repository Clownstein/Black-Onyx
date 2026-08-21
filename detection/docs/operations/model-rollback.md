# Runbook: Model rollback

## Symptoms

- Spike in false positives / false negatives after promotion
- Drift metrics recommendation `retrain_candidate` with rising FP rate
- Canary cohort quality worse than champion

## Impact

- Analyst alert fatigue or missed detections for tenants on the bad version

## Immediate actions

1. Identify the model (`log-model`, `code-model`, `network-model`, `metrics-model`) and current `@champion` version.
2. Call training-orchestrator rollback:
   - `POST /api/v1/models/{model_name}/versions/{current}/rollback`
3. Confirm `model_aliases` (or MLflow alias) now points champion to `previous_version`.
4. If canary is bad, set canary alias back to the last known-good version or set `CANARY_PERCENT=0` on model-gateway.

## Recovery

1. Keep the failed version as `@candidate` or `@shadow` only.
2. Capture metrics.json / drift snapshot for postmortem.
3. Do not auto-promote until evaluation gates pass.

## Verification

- Champion alias version matches expected previous release
- Alert rate and score distribution return toward baseline
- Shadow/canary traffic no longer serves the bad artifact as primary
