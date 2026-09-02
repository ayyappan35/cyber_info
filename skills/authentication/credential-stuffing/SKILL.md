---
skill_id: credential-stuffing
name: Credential Stuffing Detection
category: authentication
version: 1.1.0
owner_agent: security_gateway.authentication
implementation: security_gateway/gateway.py, security_gateway/mcp_tools/redis_tool.py
---

# What security task is being performed

Distinguishes a *spray-shaped* pattern (many different accounts, each
tried once or twice, from one source - the signature of credential
stuffing using a leaked username/password list, where each account is
tried with its OWN distinct breached credential) from `brute-force`
(many attempts against ONE account). The Supervisor Agent selects this
skill over `brute-force` specifically because of that "many distinct
accounts, one source" shape (`detection.yaml`'s `routing` rule), not
because of severity - a spray across 3 accounts and 20 failures against
1 account are both real attacks, just different ones needing different
framing for the LLM.

This skill's own signal (`distinct_usernames_from_source_5min`) can't
tell whether those distinct accounts are being tried with DIFFERENT
passwords (credential stuffing proper) or the SAME password repeated
(true password spraying) - see `skills/authentication/password-spraying`
(v1.0.0, 2026-09-02) for that more specific, stronger signal. Both skills
are always fed to the Security LLM together (see supervisor_agent.py);
a real spray attack will typically trigger both.

# How the agent should investigate

`distinct_usernames_from_source_5min` (new evidence field,
`redis_tool.get_distinct_usernames`, tracked per source IP via
`record_username_attempt`) is the defining signal - this skill only fires
when the Supervisor Agent's routing rule already matched on it (>= 3
distinct usernames from one source in 5 minutes), so the discussion's job
is judging severity/confidence, not re-detecting the pattern from
scratch. Consider whether the successes among those attempts (if any)
look like real accounts being compromised versus the whole batch failing
(pure spray, no compromise yet - still worth flagging, lower urgency).

# What evidence should be collected

Same authentication evidence as `brute-force`, plus
`distinct_usernames_from_source_5min`. Retrieved knowledge:
`search_threat_knowledge("credential stuffing password spray")`.

# What security boundaries apply

- `detection.yaml`'s `floor` (`distinct_usernames_from_source_5min >= 10
  -> BLOCK`) is a harder trigger than brute-force's floor, reflecting
  that a spray touching 10+ accounts from one source has essentially no
  innocent explanation.
- `response.yaml` sets a longer `block_ttl_seconds` than brute-force's
  default - a source spraying credentials warrants a longer cooldown than
  one account's repeated typos.

# How the result should be verified

Same as `brute-force`: `redis_tool.is_blocked()` re-read after BLOCK.

# MCP Tools

Same catalog as `authentication/brute-force/SKILL.md` -
`get_login_attempts`/`get_ip_reputation`/`rate_limit_user`/`require_mfa`
auto-execute, `block_ip`/`terminate_session` require admin approval. A
credential-stuffing pattern (many distinct accounts, one source) makes
`block_ip` the more naturally-fitting proposal than an account-scoped
tool - the source is the actual attacker, not any one targeted account.
