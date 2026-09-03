---
skill_id: account-takeover
name: Account Takeover Detection
category: authentication
version: 1.0.0
owner_agent: security_gateway.authentication
implementation: security_gateway/gateway.py
---

# What security task is being performed

Unlike `brute-force`/`credential-stuffing`, which reason about a pattern
of *failures*, this skill fires on a *success* that breaks an
established suspicious context - the moment a login actually succeeds
right after this same account showed heavy recent failed-attempt
pressure. That combination (success immediately following an attack
pattern against the SAME account) is the signature of a takeover: either
the attacker finally guessed right, or a credential leaked elsewhere is
being used here for the first time.

# How the agent should investigate

The Supervisor Agent selects this skill (over brute-force) specifically when
`this_attempt_success` is true AND `failed_attempts` (before this
successful attempt reset it) was already elevated
(`detection.yaml`'s routing rule). The discussion should reason about
whether this looks like the legitimate owner finally getting their own
password right (plausible, common, usually low `failed_attempts`) versus
a longer failure streak suddenly succeeding (more suspicious - consider
proposing the `terminate_session` MCP tool: it sets a cutoff that
invalidates every token issued for this user BEFORE the call - i.e. any
session an attacker already established earlier - while still letting
this request's own, just-issued token (created after `analyze()` returns
- see `backend/routers/auth_router.py`) go through. See MCP Tools below).

# What evidence should be collected

Same authentication evidence as `brute-force`. Retrieved knowledge:
`search_threat_knowledge("account takeover session compromise")`.

# What security boundaries apply

- This skill has no `floor` in `detection.yaml` - there is no
  unambiguous numeric threshold for "was this success actually the
  attacker," unlike brute-force/credential-stuffing's attempt-count
  floors. The LLM's judgment plus `policies/security_gateway_policy.yaml`'s
  `min_confidence_to_enforce` clamp is the only gate here - a deliberate
  choice, not an oversight.
- MITIGATE for this skill is logged (`siem_tool`) and sandboxed as
  evidence for admin review (`response.yaml` overrides MITIGATE's effect
  to `sandbox_and_continue`, since account-takeover's category default is
  `log_only`).

# How the result should be verified

Sandboxed evidence is re-read (`sandbox_tool.get()`) to confirm the flag
was actually recorded before the decision is reported as enforced. A
proposed `terminate_session` call is re-read via
`webapp_db.app_users.sessions_invalidated_before` before being reported
as enforced (`security_gateway/mcp_gateway.py::_exec_terminate_session`).

# MCP Tools

Same catalog as `authentication/brute-force/SKILL.md`. `terminate_session`
(kill any session the attacker may have already established) and
`require_mfa` (hold the account pending review) are the two most
relevant proposals here. `terminate_session` is risk=critical and
requires admin approval; `require_mfa` is risk=high but auto-executes,
since it only restricts further access rather than destroying live state.

`require_mfa` generates a real one-time code, hashed and stored against
the account (`webapp_db.mfa_otp_hash`/`mfa_otp_expires_at`), and emails
it via `security_gateway/mcp_tools/mail_tool.py` (real SMTP when
`SMTP_HOST` is configured, otherwise a real, admin-inspectable local
outbox - `GET /api/admin/mail-outbox` - never a fake/no-op send). The
account owner clears the hold themselves by submitting that code to
`POST /api/auth/verify-otp`; an admin can still clear it directly
(`POST /api/admin/users/{username}/clear-mfa-hold`) for a user who can't
reach their registered email.
