# Runbook: Model rollback

1. Identify the failing model (`log-model`, `code-model`, `network-model`, `metrics-model`).
2. Confirm previous healthy version via training-orchestrator aliases or MLflow.
3. Call `POST /api/v1/models/{model_name}/versions/{previous}/rollback` (or set alias `@champion` to previous).
4. Verify Model Gateway routes `requested_version=production` to the rolled-back deployment.
5. Confirm inference latency and score distribution stabilize.
6. File an incident note with dataset/model versions involved.

Target: under 30 minutes (MVP), under 10 minutes (production).
