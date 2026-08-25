# Runbook: User Enumeration

## Detection signals
- Repeated calls that list or probe valid usernames without attempting authentication, often preceding a targeted credential attack.
- A burst of `login_fail` events with `detail` containing "unknown user", interleaved with attempts against usernames that do exist — this pattern shows an attacker validating which accounts are real before attacking them.

## MITRE ATT&CK mapping
- T1589.001 — Gather Victim Identity Information: Credentials (recon phase)
- Frequently a precursor to T1110 (Brute Force)

## OWASP mapping
- OWASP Top 10 A07:2021 — Identification and Authentication Failures

## Recommended response
1. Enumeration alone does not compromise an account, but it is a strong precursor signal — raise a `medium` severity alert to establish a paper trail.
2. Watch the same source IP closely for the next several minutes; enumeration is very frequently followed immediately by targeted brute force against the confirmed usernames.
3. No account action (lock) is needed for enumeration alone since no specific account is yet under attack — reserve `lock_account` for when a specific account shows real attack signal (failed logins, replay, anomalous success).
