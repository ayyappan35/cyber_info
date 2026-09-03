---
skill_id: mfa-fatigue
name: MFA Fatigue / Prompt Bombing Detection
category: authentication
version: 1.0.0
owner_agent: security_gateway.authentication
implementation: security_gateway/gateway.py, security_gateway/mcp_tools/redis_tool.py, backend/routers/auth_router.py
---

# What security task is being performed

**Honest scope note first (CLAUDE.md Rule 3 - no fake implementations):**
the classic "MFA fatigue" / "prompt bombing" attack targets push-based
MFA (repeated push notifications until the real user gets annoyed and
taps Approve). This build's MFA (`skills/authentication/account-takeover`'s
`require_mfa` tool) is an emailed one-time code, not a push notification
- there is no "tap Approve" for an attacker to exploit that way. What this
skill actually detects is the real analog available in an OTP-based
design: an account that keeps getting RE-CHALLENGED in a short window
(`mfa_challenges_presented_10min`, incremented every time
`backend/routers/auth_router.py`'s login endpoint actually returns
`mfa_required=true` for this account) - an attacker who already has the
correct password repeatedly hitting login, either hoping the real owner
gets confused/annoyed into forwarding a code, or simply probing whether
the hold has been cleared yet.

# How the agent should investigate

`mfa_challenges_presented_10min` climbing while the SAME account keeps
submitting a correct password (implied by reaching this branch at all -
`auth_router.py` only records a challenge after `success=true`) is the
signature: a legitimate account owner who forgot they were on hold might
retry once or twice; a sustained stream of correct-password-but-still-held
attempts in a short window is someone with the password trying to force
the issue. This is distinct from `verify-otp`'s own rate limit (5 wrong
CODE guesses/5 min, in `auth_router.py`) - that guards against
brute-forcing the 6-digit code itself; this skill is about the re-challenge
RATE, regardless of whether any code was ever actually submitted.

# What evidence should be collected

`security_gateway/gateway.py::gather_authentication_evidence()`. Retrieved
knowledge: `search_threat_knowledge("mfa fatigue prompt bombing")`.

# What security boundaries apply

- No floor enforced on this experimental branch (see
  `skills/authentication/account-takeover/SKILL.md`).
- This skill can only ever fire on an account that already has
  `mfa_hold=true` from a prior account-takeover verdict - it never
  independently sets the hold, only reasons about repeated pressure
  against an existing one.

# How the result should be verified

`rate_limit_user`'s effect is re-read via `redis_tool.is_blocked`/the
identity's remaining TTL the same way brute-force's does. `require_mfa`
being re-proposed is verified the same way account-takeover's already is
(`webapp_db.app_users.mfa_hold` re-read).

# MCP Tools

Same catalog as the other authentication skills. `rate_limit_user` (slow
down further correct-password-but-held attempts against this account) is
the naturally-fitting response - it doesn't re-send another OTP
(`require_mfa` already handles that idempotently in `auth_router.py`
itself), it just makes repeated pressure against the account more costly
for whoever is applying it.
