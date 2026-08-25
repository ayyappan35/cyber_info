"""Real (not simulated-in-memory, not faked) registry of the agents that
can send a message through backend/routers/agent_router.py's
POST /api/agents/message - the source of truth skills/agents/tool-abuse
and skills/agents/privilege-escalation check against.

"Do not automatically trust another agent" (CLAUDE.md 4.5) means an
agent's role and tool access are never taken from what the message itself
claims - always from this registry (security_db.registered_agents),
mutated only through audited paths (register_agent at setup time,
change_agent_role only via a human admin, revoke/remove only via the real
MCP tools in security_gateway/mcp_gateway.py).

Honesty note (matches this project's pattern elsewhere, e.g. red_team/):
there is no autonomous multi-agent runtime in this build for a message to
arrive from organically - backend/routers/agent_router.py's endpoint is a
real, fully-enforced surface (not a stub), but it is triggered by an
admin submitting a message on an agent's behalf (the same way this
project's Red Team scenarios are admin-triggered simulations, not live
autonomous attackers) rather than by a live second agent process.
"""
from common import security_db

# Seeded once at process startup (backend/main.py's lifespan) so the demo
# has real, queryable rows to test against without requiring manual setup
# every time. register_agent() is an upsert, so re-seeding on restart is
# safe and idempotent.
_DEFAULT_AGENTS = [
    # A low-trust agent that should never be able to reach an
    # authentication-category tool like block_ip/terminate_session - only
    # a narrow, low-risk lookup.
    {"agent_id": "reporting_agent", "role": "viewer", "allowed_tools": ["get_ip_reputation"]},
    # A high-trust agent, deliberately registered WITH block_ip/
    # terminate_session in its own allowed_tools - demonstrates that even
    # a fully-authorized agent identity still can't get those tools to
    # execute via the agent-to-agent path, because mcp_gateway.py's
    # TOOL_CATALOG never granted "agent_security" as an allowed_categories
    # entry for them (a second, independent boundary - see
    # mcp_gateway.py's comment on that decision).
    {"agent_id": "ops_admin_agent", "role": "admin",
     "allowed_tools": ["get_ip_reputation", "block_ip", "terminate_session"]},
]


def seed_default_agents() -> None:
    for spec in _DEFAULT_AGENTS:
        if security_db.get_registered_agent(spec["agent_id"]) is None:
            security_db.register_agent(spec["agent_id"], spec["role"], spec["allowed_tools"])


def get_agent(agent_id: str):
    return security_db.get_registered_agent(agent_id)


def list_agents():
    return security_db.list_registered_agents()


def register_agent(agent_id: str, role: str, allowed_tools: list) -> None:
    security_db.register_agent(agent_id, role, allowed_tools)


def change_agent_role(agent_id: str, new_role: str, changed_by: str) -> dict:
    """The only real, audited way an agent's role changes - anything else
    (a direct DB edit, a compromised process mutating state) shows up as
    an unaudited difference skills/agents/privilege-escalation's floor
    catches."""
    agent = security_db.get_registered_agent(agent_id)
    if agent is None:
        raise ValueError(f"No registered agent '{agent_id}'")
    security_db.record_agent_role_change(agent_id, old_role=agent["role"], new_role=new_role, changed_by=changed_by)
    return security_db.get_registered_agent(agent_id)


def disable_agent(agent_id: str) -> None:
    security_db.set_agent_disabled(agent_id, True)


def remove_tool_access(agent_id: str, tool_name: str) -> dict:
    agent = security_db.get_registered_agent(agent_id)
    if agent is None:
        raise ValueError(f"No registered agent '{agent_id}'")
    remaining = [t for t in agent["allowed_tools"] if t != tool_name]
    security_db.set_agent_allowed_tools(agent_id, remaining)
    return security_db.get_registered_agent(agent_id)


def session_start_role(session_id: str, agent_id: str, current_role: str) -> dict:
    """Returns {"role_at_session_start", "first_seen_at"} - recorded on
    first sight of this (session_id, agent_id) pair, immutable after."""
    return security_db.get_or_start_agent_session(session_id, agent_id, current_role)


def role_change_event_id_since(agent_id: str, since_ts: str):
    change = security_db.latest_role_change_since(agent_id, since_ts)
    return change["id"] if change else None
