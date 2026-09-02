---
skill_id: brute-force
name: Brute Force Detection
category: authentication
version: 2.0.0
owner_agent: security_gateway.authentication
implementation: security_gateway/gateway.py, security_gateway/detection.py, security_gateway/mcp_tools/redis_tool.py
---

# What security task is being performed

This is the default authentication skill: repeated failed attempts
concentrated against ONE account, from ONE source. `detection.yaml`'s
`routing` rule for `credential-stuffing` (many distinct accounts from one
source) and `account-takeover` (a success that breaks an established
suspicious pattern) are checked first by the Supervisor Agent
(`security_gateway/supervisor_agent.py`); brute-force is what's left when
neither of those more specific patterns match - marked `default: true`.

# How the agent should investigate

Evidence handed to the Security LLM Discussion node (see `detection.yaml`
`signals`): this account's `failed_attempts` and `locked` state
(`webapp_db.py`, real columns), `recent_attempt_count_1min` for this
specific username, whether this identity is already block-listed, and
whether *this* attempt succeeded. The model should distinguish a genuine
attack pattern (many failures, tight timing) from normal human error
(one or two mistyped passwords) - `detection.yaml`'s `floor` is a
deterministic backstop for the unambiguous case (>=5 attempts in a single
minute - tightened 2026-09-01 from >=20 in 5 minutes), not a replacement
for this judgment on the ambiguous middle ground.

# What evidence should be collected

`security_gateway/gateway.py::gather_authentication_evidence()`. Retrieved
knowledge: `search_threat_knowledge("brute force attack pattern")`.

# What security boundaries apply

- `detection.yaml`'s `floor` (`recent_attempt_count_1min >= 5 ->
  minimum_action: BLOCK`) is enforced in `security_gateway/detection.py`
  BEFORE the LLM's own clamped action is compared - the LLM can propose a
  stronger action, never a weaker one once the floor is crossed.
- BLOCK adds the identity to the Redis/local block list
  (`policies/security_gateway_policy.yaml`'s `redis_block` effect);
  `response.yaml` in this directory sets this skill's own
  `block_ttl_seconds`, overriding the category default.
- `webapp_db.LOCKOUT_THRESHOLD`'s account-level lock (3 consecutive failed
  attempts - see knowledge/security_policies/account_lockout_policy.md) is
  a separate, always-on deterministic control, never weakened by this
  skill - it can lock the ACCOUNT well before this skill's own
  5-attempts-in-1-minute floor (below) is ever reached (in fact
  LOCKOUT_THRESHOLD=3 now fires strictly BEFORE this floor's threshold of
  5 in the common case of one attempt per request). Don't conflate the
  two: 3 failed attempts locks the account (can't log in at all,
  regardless of what this discussion concludes); 5 attempts in 1 minute
  is this skill's own floor that forces a Redis/local IDENTITY block via
  the gateway - a different mechanism entirely, and the one that actually
  matters for a distributed/scripted attack where each attempt targets a
  *different* recently-created account (never tripping any one account's
  LOCKOUT_THRESHOLD) but still hammers one identity's login endpoint.

# How the result should be verified

`security_gateway/gateway.py`'s verification step re-reads
`redis_tool.is_blocked(identity, "authentication")` after a BLOCK and
only reports it enforced if that read confirms it.

# MCP Tools

The discussion may propose tool NAMES only (never arguments -
`security_gateway/mcp_gateway.py` fills those in deterministically from
already-known evidence/identity):

- `get_login_attempts` - risk low, auto-executed, read-only.
- `get_ip_reputation` - risk low, auto-executed, read-only, internal
  history only (no external threat-intel feed exists in this build).
- `rate_limit_user` - risk medium, auto-executed. Appropriate for a
  MITIGATE-tier proposal.
- `require_mfa` - risk high, auto-executed. Sets an admin-clearable
  access hold (`webapp_db.app_users.mfa_hold`) - not a real second-factor
  challenge, this build has none.
- `block_ip` - risk critical, **requires admin approval** before it
  executes (`GET/POST /api/security/tool-calls*`).
- `terminate_session` - risk critical, **requires admin approval**.

