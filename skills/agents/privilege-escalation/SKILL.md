---
skill_id: privilege-escalation
name: Agent Privilege Escalation Detection
category: agents
version: 1.1.0
owner_agent: security_gateway.gateway
implementation: real - request_category="agent_security", see "current status" below
---

# Current status: wired to a real enforcement path (2026-08-24)

Detecting an agent's own role/trust-level changing over the course of a
session without an explicit, auditable admin action causing it - e.g. an
agent that started as `role=viewer` later executing an action gated to
`role=admin`. Distinct from `tool-abuse` (using a tool outside scope) -
this is about the agent's *identity/role itself* changing.

`security_gateway/agent_registry.py::session_start_role()` records each
agent's role, from the real registry, the first time it's seen in a
given `session_id` (`security_db.agent_sessions`) - immutable after. The
ONLY real, audited way that role can legitimately differ later is a
logged `security_db.agent_role_changes` row, created by
`agent_registry.change_agent_role()` (a human admin action - never
something an agent does to itself). Anything else is the signature. See
`agents/tool-abuse/SKILL.md` for the honesty note on how the endpoint is
triggered (admin-simulated messages, no autonomous multi-agent runtime).

# How the agent should investigate

Compare an agent's role at session start against its role at the moment
of each sensitive action; any difference not covered by a logged, human-
attributed role-change event since session start is the signature -
this app's real `PATCH /api/admin/users/{username}/role` was the only
precedent for human-attributed role changes before this; agents now have
their own equivalent (`agent_registry.change_agent_role()`).

# What evidence should be collected

`detection.yaml`'s `signals`: `agent_id`, `role_at_session_start`,
`role_at_action_time`, `role_changed` (the two compared - computed here,
not inline in YAML, since the detection.yaml condition evaluator only
compares a field against a literal, never two evidence fields against
each other), `role_change_event_id` (null if none logged) - all computed
by `security_gateway/gateway.py::gather_agent_security_evidence()`.

# What security boundaries apply

Once a real audited role-change record exists to compare against, an
unexplained difference is unambiguous - this is why the floor below is a
hard `BLOCK`, not LLM-judged, matching `tool-abuse`'s reasoning.

# How the result should be verified

Same verification pattern this project uses throughout: re-read the
agent's actual current role/status (`agent_registry.get_agent()`) after
any corrective action (`revoke_agent_credentials`), never report success
from the action call's return value alone.
