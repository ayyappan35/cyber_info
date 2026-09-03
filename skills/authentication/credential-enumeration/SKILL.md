---
skill_id: credential-enumeration
name: Credential/Username Enumeration Detection
category: authentication
version: 1.0.0
owner_agent: security_gateway.authentication
implementation: security_gateway/gateway.py, security_gateway/mcp_tools/redis_tool.py
---

# What security task is being performed

Distinct from every other authentication skill here: this one fires on
attempts against accounts that DON'T EXIST, not on failures against real
ones. An attacker probing a login form to discover which usernames are
valid (before ever trying to guess a password) produces a burst of
`account_exists=false` results from one source - the reconnaissance step
that typically precedes brute-force/credential-stuffing/password-spraying,
not an attack on any one real account.

# How the agent should investigate

`this app already defends the passive side of enumeration (identical
"Invalid username or password" text and matched bcrypt timing for both a
wrong password AND a nonexistent account - see `auth.py::DUMMY_PASSWORD_HASH`),
so an attacker can't learn anything from a SINGLE response. The signal
this skill looks for instead is volume: how many attempts against
nonexistent usernames has this one source made recently
(`nonexistent_account_attempts_from_source_5min`)? A handful is
plausible (a user mistyping their own username, an old bookmark), a
sustained stream from one source is reconnaissance.

# What evidence should be collected

`security_gateway/gateway.py::gather_authentication_evidence()`. Retrieved
knowledge: `search_threat_knowledge("username enumeration reconnaissance")`.

# What security boundaries apply

- No floor is enforced on this experimental branch (`security_gateway/
  gateway.py`'s docstring - `detection.yaml`'s `routing`/`floor` sections
  are inert documentation here, not live code; see
  `skills/authentication/account-takeover/SKILL.md` for the same note on
  a sibling skill). The numbers below describe what the signal MEANS, not
  a threshold this build enforces on its own.
- This skill can fire alongside credential-stuffing/password-spraying on
  the same evidence (a source enumerating usernames often pivots straight
  into guessing passwords against the ones that came back "exists") -
  `matched_skill_ids` can legitimately report more than one.

# How the result should be verified

Same as brute-force/password-spraying: `redis_tool.is_blocked(source_ip
or identity, "authentication")` re-read after a BLOCK, and the
`block_ip`/`rate_limit_user` tool results themselves re-checked before
being reported enforced.

# MCP Tools

Same catalog as the other authentication skills. `get_login_attempts`
and `get_ip_reputation` are read-only first steps. `block_ip` is the
naturally-fitting containment here (same reasoning as password-spraying's
SKILL.md: the SOURCE is the attacker, not any one targeted username -
most of the attempted usernames aren't even real accounts).
`rate_limit_user` doesn't fit well on its own for THIS skill (rate-limiting
a username that doesn't exist accomplishes nothing); the model should lean
on `block_ip` if it decides to act.
