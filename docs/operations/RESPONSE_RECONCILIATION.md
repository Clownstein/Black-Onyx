# Response execution reconciliation

An approved live playbook changes external systems. If the response service loses its result after claiming a request, it cannot know whether a firewall, EDR, capture, or DNS action took effect. It must not replay that request.

In **Response queue → Execution outcomes to verify**, select **Check stale executions**. The BFF supplies the server-held approver key; the browser never receives it. The scan marks requests that have remained `executing` longer than `RESPONSE_ORCHESTRATOR_EXECUTION_UNCERTAIN_AFTER_SECONDS` (default 600) as `execution_uncertain` and writes an audit event. Listing the results is read-only. The API does not allow approval or rejection of an uncertain request.

For each uncertain request, inspect the external system's action log and the response audit trail using the request, incident, target, and time. Record the observed outcome in the incident record. If the action did not occur and remains necessary, create a new response request and take it through preview and approval. Do not retry the old request: the service intentionally has no automatic replay path.

The scan prevents automatic replay by this service; it does not provide
exactly-once execution at an external provider. Integrations that require
automated recovery must use provider-specific idempotency keys and verify the
result through provider readback.
