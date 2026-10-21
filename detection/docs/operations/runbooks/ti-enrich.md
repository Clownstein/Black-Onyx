# Runbook: Threat intel enrichment checklist

Symptoms: incident with external indicators (IP, domain, hash) needing context; threat-intel exact or semantic matches to review.

1. Extract observables from incident evidence and findings (IPs, domains, hashes, URLs).
2. Query threat-intel: run exact match (`/api/v1/match`) and, when enabled, semantic match (`/api/v1/match/semantic`).
3. Review confidence: treat semantic hits as advisory (capped confidence); prioritize exact matches and KEV-flagged indicators.
4. Correlate campaigns and ATT&CK techniques returned by the match result.
5. Decide response: enrich the incident, escalate, or open a containment playbook as warranted.
6. Verify: record enrichment findings and TLP handling on the incident.
