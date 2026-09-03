---
skill_id: impossible-travel
name: Impossible Travel Detection
category: authentication
version: 1.0.0
owner_agent: security_gateway.authentication
implementation: security_gateway/gateway.py, security_gateway/mcp_tools/redis_tool.py
---

# What security task is being performed

**Honest scope note first (CLAUDE.md Rule 3 - no fake implementations):**
this build has no geo-IP database and does no real
distance/travel-time calculation. What it actually detects is the
proxy signal real "impossible travel" detectors are built on before the
geolocation step is added: the SAME account being used from multiple
DISTINCT source IPs within a short window
(`distinct_source_ips_for_account_15min`). Real geographic impossible
travel (Chennai then Tokyo eight minutes apart) is a special case of
this broader pattern; a shared/leaked credential being used from two
unrelated networks in quick succession is the other common cause this
signal also legitimately catches, and is arguably the more common
real-world case for this class of app.

# How the agent should investigate

Distinguish a genuinely suspicious pattern (2+ distinct source IPs for
one account in 15 minutes, especially if this attempt is a SUCCESS) from
an explainable one (the account owner switching from home wifi to mobile
data mid-session, a VPN reconnecting with a new exit IP - both produce a
new source IP for a legitimate user too). The model should weigh
`this_attempt_success` heavily here: a failed attempt from a second IP
while the account is already in active, legitimate use elsewhere reads
very differently from a SUCCESSFUL login from a second IP.

# What evidence should be collected

`security_gateway/gateway.py::gather_authentication_evidence()`. Retrieved
knowledge: `search_threat_knowledge("impossible travel session hijacking")`.

# What security boundaries apply

- No floor enforced on this experimental branch (see
  `skills/authentication/account-takeover/SKILL.md` for why floors are
  inert documentation here, not live code).
- Unlike brute-force/password-spraying, `block_ip` doesn't make sense as
  a primary response here - by definition there are at least two source
  IPs involved, and blocking one doesn't stop use of the other. The
  account-scoped tools (`require_mfa`, `terminate_session`) are the ones
  that actually address this pattern.

# How the result should be verified

`require_mfa`'s hold is re-read (`webapp_db.app_users.mfa_hold`) the same
way account-takeover verifies it. A proposed `terminate_session` is
re-read via `webapp_db.app_users.sessions_invalidated_before`
(`security_gateway/mcp_gateway.py::_exec_terminate_session`) before being
reported enforced.

# MCP Tools

Same catalog as `authentication/account-takeover/SKILL.md`.
`terminate_session` (invalidate whatever session the OTHER source IP may
have already established) and `require_mfa` (force re-verification
before either source can continue) are the two tools that actually fit
this pattern - both account-scoped, since the attack signature itself is
account-scoped, not source-scoped.
