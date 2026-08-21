# Runbook: Credential reset after compromise

Symptoms: credential compromise, brute-force/password-spray findings, anomalous or impossible-travel logins, valid-account abuse.

1. Confirm: review log/identity findings for the affected account(s).
2. Scope: enumerate active sessions, tokens, and accessed services.
3. Reset: force password reset, revoke active sessions and refresh tokens, require MFA re-enrollment.
4. Hunt persistence: check for attacker-created API keys, OAuth grants, and mail rules.
5. Eradicate: remove malicious credentials and revoke compromised keys.
6. Verify: confirm no further anomalous logins and record disposition.
