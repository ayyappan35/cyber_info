---
skill_id: password-spraying
name: Password Spraying Detection
category: authentication
version: 1.0.0
owner_agent: security_gateway.authentication
implementation: security_gateway/gateway.py, security_gateway/mcp_tools/redis_tool.py
---

# What security task is being performed

Distinguishes true password *spraying* (ONE password, or a small common
set, tried across MANY DIFFERENT accounts from one source) from
`credential-stuffing` (many different accounts, each tried with its OWN
distinct breached password) - both produce "many distinct usernames from
one source" on their own, but only spraying also shows the SAME password
value repeating across those usernames. This is a real, observed gap
this skill closes: `credential-stuffing`'s existing signal
(`distinct_usernames_from_source_5min`) can't tell the two apart, and a
classic low-and-slow spray (one guess per account, using a common
password like "Autumn2026!") can sit well under credential-stuffing's
own floor while still being an unambiguous attack.

# How the agent should investigate

`distinct_usernames_same_password_5min` is the defining signal
(`security_gateway/gateway.py::gather_authentication_evidence`,
`redis_tool.get_distinct_usernames_for_password`) - how many distinct
usernames have been attempted with the EXACT SAME submitted password,
from this source, in the trailing 5 minutes. This is a stronger signal
than credential-stuffing's alone: real, independent users essentially
never coincidentally submit identical password strings from the same
source in a short window, so even a modest count here has very low
false-positive risk. The model should still weigh `this_attempt_success`
- a spray that succeeds against one of the tried accounts is a live
compromise, not just a probing attempt.

# What evidence should be collected

Same authentication evidence as `brute-force`, plus
`distinct_usernames_same_password_5min`. Retrieved knowledge:
`search_threat_knowledge("password spraying attack common passwords")`.

# What security boundaries apply

- `detection.yaml`'s `floor` (`distinct_usernames_same_password_5min >= 5
  -> BLOCK`) triggers at a LOWER count than credential-stuffing's floor
  (10) specifically because same-password-across-accounts is a stronger,
  less ambiguous signal than distinct-accounts-alone - fewer occurrences
  are needed before it has no innocent explanation.
- `response.yaml` sets a longer `block_ttl_seconds` than brute-force's
  default, matching credential-stuffing's - a spraying source is more
  likely automated/persistent than one account's repeated typos.
- The submitted password is NEVER stored or logged in any form here -
  `gather_authentication_evidence` computes a plain SHA-256 of it purely
  as a same-value CORRELATION key (does this attempt's password match a
  prior attempt's, not what the password actually is), passed to
  `redis_tool.record_password_attempt`/`get_distinct_usernames_for_password`,
  which hold it only in the same short-lived, in-process/SQLite-fallback
  tracking state `brute-force`/`credential-stuffing` already use (evicted
  by the sliding window, never persisted long-term, never exposed via any
  API). This is a correlation hash, not a security hash - see
  `redis_tool.py::record_password_attempt`'s docstring for the honest
  tradeoff that makes.

# How the result should be verified

Same as `brute-force`/`credential-stuffing`: `redis_tool.is_blocked()`
re-read after BLOCK.

# MCP Tools

Same catalog as `authentication/credential-stuffing/SKILL.md` -
`get_login_attempts`/`get_ip_reputation`/`rate_limit_user`/`require_mfa`
auto-execute, `block_ip`/`terminate_session` require admin approval.
`block_ip` is the naturally-fitting proposal here too - the source is the
actual attacker, not any one targeted account.
