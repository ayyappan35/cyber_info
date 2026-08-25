# Policy: Account Lockout & Escalation

## Automatic lockout
- Accounts automatically lock after 5 consecutive failed password attempts. This is enforced by the auth system itself, not by the SOC agent.

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
