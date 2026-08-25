# Runbook: Session Token Replay / Hijacking

## Detection signals
- A `session_replay` event: the same session token used from a second IP address or device after the original login.
- A session whose status becomes `hijacked` — this means an attacker successfully reused a leaked/stolen token without needing the password.
- Session token reuse is often preceded by no failed logins at all, because the attacker never touched the password — this makes it stealthier than brute force and easy to miss if you only watch `login_fail` events.

## MITRE ATT&CK mapping
- T1539 — Steal Web Session Cookie
- T1550.004 — Use Alternate Authentication Material: Web Session Cookie

## OWASP mapping
- OWASP Top 10 A07:2021 — Identification and Authentication Failures (broken session management)

## Recommended response
1. Treat any `session_replay` success as a confirmed compromise, not a suspicious signal — the token is already in the attacker's hands.
2. Immediately close/invalidate the affected session with `close_session` using verdict `hijacked`.
3. Lock the underlying account with `lock_account` so the legitimate user must re-authenticate and the attacker cannot re-request a new token with stolen credentials.
4. Raise a `critical` severity alert — token theft usually means logs, malware, or a man-in-the-middle position elsewhere in the environment that also needs investigating.
5. Do not rely on IP address alone to distinguish the real user from the attacker; both may appear to come from residential ISPs.
