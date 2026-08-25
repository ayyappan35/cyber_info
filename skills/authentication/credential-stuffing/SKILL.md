---
skill_id: credential-stuffing
name: Credential Stuffing / Password Spray Detection
category: authentication
version: 1.0.0
owner_agent: security_gateway.authentication
implementation: security_gateway/gateway.py, security_gateway/mcp_tools/redis_tool.py
---

# What security task is being performed

Distinguishes a *spray* (many different accounts, each tried once or
twice, from one source - the signature of credential-stuffing using a
leaked username/password list) from `brute-force` (many attempts against
ONE account). The Threat Router selects this skill over `brute-force`
specifically because of that "many distinct accounts, one source" shape
(`detection.yaml`'s `routing` rule), not because of severity - a spray
across 3 accounts and 20 failures against 1 account are both real
attacks, just different ones needing different framing for the LLM.

# How the agent should investigate

`distinct_usernames_from_source_5min` (new evidence field,
`redis_tool.get_distinct_usernames`, tracked per source IP via
`record_username_attempt`) is the defining signal - this skill only fires
when the Threat Router's routing rule already matched on it (>= 3
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
