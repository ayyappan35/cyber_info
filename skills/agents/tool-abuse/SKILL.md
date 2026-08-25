---
skill_id: tool-abuse
name: Agent Tool Abuse Detection
category: agents
version: 1.1.0
owner_agent: security_gateway.gateway
implementation: real - request_category="agent_security", see "current status" below
---

# Current status: wired to a real enforcement path (2026-08-24)

Detecting an agent invoking a tool outside its declared role/permission
scope - e.g. a read-only reporting agent suddenly requesting a
credential-revocation tool. The signature is a mismatch between an
agent's registered capability set (`security_gateway/agent_registry.py`,
backed by `security_db.registered_agents`) and what it's actually
requesting.

`backend/routers/agent_router.py`'s `POST /api/agents/message` is the
real invocation point: every message is checked against the sender's
REGISTERED tool set (never what the message itself claims) before
`security_gateway/gateway.py::analyze("agent_security", ...)` even runs,
and this skill's `detection.yaml` floor forces `BLOCK` deterministically
on a mismatch - not left to LLM judgment, per the design note this file
used to carry (kept below for context).

Honesty note: there is no autonomous multi-agent runtime in this build
for a message to arrive from organically - the endpoint is real and
fully enforced, but triggered by an admin submitting a message on an
agent's behalf, the same way this project's Red Team scenarios are
admin-triggered simulations rather than a live second agent process. The
prior architecture had a live version of this
(`agents/rogue_agent_detection.py`, archived under
`_archive_2026-08-24_pre_gateway_rebuild/`).

# How the agent should investigate

Compare the requested tool name against the calling agent's registered
allowed-tool list; flag any request outside that set as evidence, then
have the Security LLM Discussion node reason about whether this could be
a legitimate one-off (unlikely - tool grants shouldn't need judgment
calls) or a compromised/manipulated agent. Even when the requested tool
IS in the agent's registered set, `security_gateway/mcp_gateway.py`'s own
`TOOL_CATALOG` independently decides whether that tool is even reachable
via the agent-to-agent path at all (`allowed_categories` including
`"agent_security"`) - a second, structural boundary beyond this skill,
deliberately narrow (only `get_ip_reputation` is agent-reachable today).

# What evidence should be collected

`detection.yaml`'s `signals`: `agent_id`, `requested_tool`,
`agent_registered_tools`, `tool_in_registered_set` - computed by
`security_gateway/gateway.py::gather_agent_security_evidence()` from the
real registry, never from the message's own claims.

# What security boundaries apply

The registry (`security_db.registered_agents`) is the deterministic
source of truth - this is why the floor above is a hard `BLOCK`, not
LLM-judged, unlike most of the wired skills which reserve judgment calls
for genuinely ambiguous cases: a tool-permission mismatch against a
real registry isn't ambiguous.

# How the result should be verified

`security_gateway/mcp_gateway.py`'s `revoke_agent_credentials`/
`remove_agent_tool_access` tools (real, `allowed_categories=
["agent_security"]`, `requires_approval=True`) - the Security LLM
Discussion can propose either as a response to a violation; both re-read
`security_db.get_registered_agent()` after acting, matching this
project's verification pattern throughout.
