# Runbook: Impossible Travel / Anomalous Login Location

## Detection signals
- The same username logging in successfully from two geographically distant locations in a time window too short for real travel.
- A login from a geography or device type the account has never used before, especially combined with an off-hours timestamp.

## MITRE ATT&CK mapping
- T1078 — Valid Accounts (use of legitimate but compromised credentials)

## OWASP mapping
- OWASP Top 10 A07:2021 — Identification and Authentication Failures

## Recommended response
1. Cross-reference recent `login_success` events for the account with `query_auth_logs` — compare `geo`/`ip`/`device` fields across the account's recent history.
2. If the new login's geo/device does not match the account's established pattern, treat it as elevated risk even though the password was correct — the password may have been phished or leaked.
3. Prefer `lock_account` plus an alert over silently allowing the session; correct-password logins from anomalous locations are one of the most common real-world account-takeover patterns.
4. If the login pattern is only mildly unusual (e.g. same country, new city), a lower-severity alert without a full lockout may be proportionate — use judgment based on how anomalous the signal is.

## False positive notes
- VPNs and corporate proxies can legitimately shift a user's apparent geography. Consider frequency: a one-off anomaly is lower risk than a sustained pattern.
