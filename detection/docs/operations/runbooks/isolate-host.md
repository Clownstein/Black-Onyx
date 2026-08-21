# Runbook: Isolate host

Symptoms: confirmed host compromise, ransomware/encryption behavior, C2 beacon from an endpoint, lateral movement.

1. Confirm scope: identify the affected host(s) from incident assets and related incidents.
2. Contain: request the `isolate-host-edr` (or `isolate-host`) playbook via response-orchestrator; approval is required and vector-only signals never auto-execute.
3. Preserve evidence: capture volatile memory and relevant PCAP before any reimage.
4. Investigate: review host findings for persistence and privilege changes.
5. Recover: reimage or restore from known-good state after eradication.
6. Verify: confirm no further malicious activity, then record disposition.
