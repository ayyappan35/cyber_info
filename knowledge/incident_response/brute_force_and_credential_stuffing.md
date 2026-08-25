# Runbook: Brute Force / Credential Stuffing on Login

## Detection signals
- Multiple `login_fail` events for the same username within a short window (5+ failures in under 2 minutes).
- Multiple `login_fail` events for many different usernames from the same source IP (credential stuffing, not targeted brute force).
- Failed attempts using common/weak passwords (e.g. `admin123`, `password1`).

## MITRE ATT&CK mapping
- T1110 — Brute Force
- T1110.004 — Credential Stuffing

## OWASP mapping
- OWASP Top 10 A07:2021 — Identification and Authentication Failures

## Recommended response
1. If failed attempts for one account exceed the lockout threshold, the account should already be locked automatically — verify with `query_auth_logs`.
2. If not yet locked, call `lock_account` immediately to stop further guessing.
3. Raise an alert with severity `high` if the source IP is hitting multiple distinct usernames (credential stuffing pattern) — this indicates a leaked password list, not a single-target attack.
4. Do not unlock the account without out-of-band verification of the real user's identity.
5. Document the source IP for later blocklisting.

## False positive notes
- A single failed login followed by a successful one from the same IP/device is normal user error, not an attack. Do not escalate on a single failure.
