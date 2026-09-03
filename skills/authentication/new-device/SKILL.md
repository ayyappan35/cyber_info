---
skill_id: new-device
name: New Device Login Detection
category: authentication
version: 1.0.0
owner_agent: security_gateway.authentication
implementation: security_gateway/gateway.py, backend/webapp_db.py
---

# What security task is being performed

**Honest scope note first (CLAUDE.md Rule 3 - no fake implementations):**
`security_gateway/mcp_gateway.py` already documents that this build does
NO device fingerprinting (no canvas/TLS/behavioral signal, no device_id
capture). What this skill actually uses is a real but coarse signal: the
literal `User-Agent` HTTP header a login request carried, checked against
`webapp_db.known_user_agents` - has THIS account ever successfully logged
in with THIS exact User-Agent string before? A real signal (an actual
header, not fabricated), but coarse: many real users legitimately share
identical User-Agent strings (same browser/OS/version), so this should be
read as "a login using a browser/OS combination not previously seen on
this account," not "a login from a specific physical device."

# How the agent should investigate

`user_agent_seen_before_for_account=false` on a brand-new account's very
first-ever login is expected and NOT suspicious
(`known_user_agent_count_for_account=0` in that case - use it to tell
"first login ever" apart from "5th known device, this one's new"). The
interesting case is an ESTABLISHED account (several known user-agents
already) suddenly succeeding from one that's never been seen, especially
combined with other signals this same evidence dict carries (elevated
`failed_attempts`, a new `distinct_source_ips_for_account_15min` value,
etc.) - new-device alone, with nothing else present, is often just the
owner buying a new phone or updating their browser.

# What evidence should be collected

`security_gateway/gateway.py::gather_authentication_evidence()`. Retrieved
knowledge: `search_threat_knowledge("new device login notification")`.

# What security boundaries apply

- No floor enforced on this experimental branch (see
  `skills/authentication/account-takeover/SKILL.md`). This is arguably
  the skill where a floor would be LEAST appropriate anyway: a
  first-time-device login is common, everyday, legitimate behavior far
  more often than it's an attack - full LLM judgment, weighed against the
  surrounding evidence, is the right fit here.
- `webapp_db.record_user_agent()` only ever runs on a SUCCESSFUL login -
  an attacker's failed attempts from their own device must never earn it
  "known" status (see that function's docstring).

# How the result should be verified

`require_mfa`'s hold is re-read (`webapp_db.app_users.mfa_hold`) the same
way account-takeover verifies it, when the model proposes it.

# MCP Tools

Same catalog as the other authentication skills. `require_mfa` (force
verification of the new device) is the natural proposal for a MITIGATE/
BLOCK-leaning case; for the common benign case (established account,
otherwise-clean evidence) `ALLOW` with no tool call at all is the
appropriate outcome - this skill matching does not by itself imply any
enforcement action.
