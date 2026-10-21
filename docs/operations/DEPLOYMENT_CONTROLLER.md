# Deployment controller runbook

Administrators change Compose and Helm deployment settings from **Settings →
Deployment** (or `/api/v1/admin/deployments`). The TIP process never holds Docker
or Kubernetes credentials; it hands approved revisions to a host-side applier.

```
draft ──approve(preview digest)──▶ approved ──apply──▶ applying ──applier──▶ active | failed
                                                        previous active ──▶ superseded
```

## Components

| Piece | Where | Role |
| --- | --- | --- |
| Settings registry | `src/black_onyx/settings_registry.py` | Every managed env setting: category, consumers, secret flag, choices, production requirement |
| Controller | `src/black_onyx/ops/deploy_controller.py` | Encrypted revisions in the state DB (`deployment_revisions`), previews, approval, signed bundles, rollback |
| Admin API | `src/black_onyx/api/routes_platform_admin.py` | `/api/v1/admin/settings/inventory`, `/api/v1/admin/deployments/*` |
| Applier | `scripts/deploy_applier.py` | Verifies bundle signatures, validates the render, applies, health-checks, restores on failure |

## Configuration

| Variable | Where | Meaning |
| --- | --- | --- |
| `BLACK_ONYX_DEPLOY_HANDOFF_DIR` | TIP (`web`) and applier host | Shared directory for signed bundles and `status.json` |
| `BLACK_ONYX_DEPLOY_SIGNING_KEY` | TIP and applier (≥32 chars) | HMAC key for bundle manifests |
| `BLACK_ONYX_DEPLOY_TWO_PERSON` | TIP | `true` requires a different administrator to approve |

Mount the handoff directory into the `web` container read-write and give only the
applier host read-write access to it. Nothing else should share it.

## Lifecycle

1. **Draft.** Enter `NAME=value` lines (and, for Helm, a JSON object of dotted
   chart value paths). `NAME=<unset>` removes a setting. The draft stores the
   full desired state encrypted at rest and a masked preview; secrets appear as
   `<set>`/`<empty>`.
2. **Approve.** The approval must quote the draft's `preview_digest`, so what an
   administrator reviewed is exactly what will apply.
3. **Apply.** Writes `<handoff>/<revision>/` with `managed.env` (Compose) or
   `managed-values.yaml` + `secret-data.json` (Helm) and a signed `manifest.json`.
   Only one revision per target may be `applying`.
4. **Applier.** Run on the host with credentials:

   ```bash
   python scripts/deploy_applier.py compose --handoff-dir /srv/black-onyx/handoff --watch \
     --env-file .env -f docker-compose.yml -f docker-compose.platform.yml \
     -f docker-compose.detection-apps.yml -f docker-compose.production.yml \
     -f docker-compose.production-detection.yml
   ```

   ```bash
   python scripts/deploy_applier.py helm --handoff-dir /srv/black-onyx/handoff --watch \
     --release black-onyx-detection --namespace black-onyx-application \
     --secret black-onyx-detection-secrets \
     -f deploy/detection/helm/black-onyx-detection/values.yaml \
     -f deploy/detection/helm/black-onyx-detection/values-prod.yaml
   ```

   Compose: `config --quiet`, then `up -d --wait`, then a service health sweep;
   on failure the previous `deploy/runtime/managed.env` is restored and `up -d`
   runs again. Helm: `helm template`, then `helm upgrade --atomic --wait`; the
   operator Secret is restored if the upgrade fails.
5. **Refresh.** The controller folds `status.json` into the revision
   (`active` + health, or `failed` + error) whenever the revision is read.

## Rollback

`POST /api/v1/admin/deployments/rollback/{target}` drafts a revision that restores
the last superseded state. It goes through the same approve → apply → health path.

## Production invariants and lab exceptions

- Deployment settings with a `production_required` value (for example
  `ENABLE_BASH_TOOL=false`, `ALLOW_PRIVATE_TARGETS=false`, `TOOL_APPROVAL=required`)
  and Helm invariants (`security.oidcDisabled=false`, `security.allowDemoKeys=false`,
  `security.requireServiceKeys=true`, `networkPolicy.denyIngressDefault=true`,
  `securityContext.runAsNonRoot=true`) cannot be changed when
  `security.production=true`.
- Outside production, a revision that violates them needs
  `lab_exception_hours` (1–72). Expired exceptions cannot be applied, and an
  active revision whose exception has expired is listed in
  `expired_exceptions` on the settings inventory so an administrator can draft
  the restoring revision.

## Audit

Every create, approve, reject, apply and applier result writes an
`audit_events` row (`target_type=deployment_revision`).
