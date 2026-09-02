# Policy: Account Lockout & Escalation

## Automatic lockout
- Accounts automatically lock after 3 consecutive failed password attempts (backend/webapp_db.py's LOCKOUT_THRESHOLD). This is enforced by the auth system itself, not by the SOC agent, and applies regardless of what the Security LLM Discussion concludes.
- This is a SEPARATE, lower threshold from the AI Security Gateway's own deterministic floor on skills/authentication/brute-force (5+ attempts against one account in a 1-minute window forces a Redis/local identity BLOCK - tightened 2026-09-01 from 20 attempts/5 minutes) - the account can already be locked well before that gateway-level floor is ever reached. Don't conflate the two: account lock = can't log in at all; gateway BLOCK = this identity is rate-limited/blocked from further attempts being evaluated.

## When the blue team should act manually before the automatic threshold
- Session replay / hijacking (immediate, any single occurrence).
- Impossible travel with a correct password (login succeeded, so no failed-attempt counter will ever trigger — automatic lockout will NOT catch this).
- Credential stuffing distributed across many accounts, where each individual account only sees 1-2 failed attempts (below the per-account threshold) but the aggregate pattern across accounts is clearly malicious.

## Severity guide for alerts
- `critical`: confirmed session hijack, or successful login immediately following a locked-out brute-force run against the same account.
- `high`: credential stuffing pattern, brute force nearing/at lockout threshold.
- `medium`: enumeration, a single anomalous-but-successful login with only mild geo/device deviation.
- `low`: isolated single failed login, normal user error patterns.

## Closing the loop
- Every investigated session should end with `close_session` carrying an explicit verdict: `benign`, `suspicious`, `hijacked`, or `blocked`. Sessions should not be left open without a verdict once the login→logout lifecycle completes.
