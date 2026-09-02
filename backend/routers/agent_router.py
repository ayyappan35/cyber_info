"""Agent-to-agent security: skills/agents/tool-abuse and .../
privilege-escalation, wired to a real enforcement path (2026-08-24).

POST /message is the real invocation point CLAUDE.md 4.5/4.6 describe -
validates identity/authorization/registered-tool-scope BEFORE the
Security LLM Discussion even runs, then a second, independent check
(security_gateway/mcp_gateway.py's own TOOL_CATALOG allowed_categories)
before the requested tool is ever actually executed. See
security_gateway/agent_registry.py's module docstring for the honesty
note on how this endpoint is triggered (admin-simulated messages - no
autonomous multi-agent runtime exists in this build for one to arrive
from organically, same as this project's Red Team scenarios).

Admin-only throughout: registering an agent identity or changing its role
is exactly the kind of "explicit, auditable admin action" skills/agents/
privilege-escalation's floor is checking FOR the absence of.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status

import auth
from common import security_db
from schemas import (AgentMessageRequest, AgentMessageResponse, AgentOut, ChangeAgentRoleRequest,
                      RegisterAgentRequest)
from security_gateway import agent_registry, gateway, mcp_gateway

router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.get("", response_model=List[AgentOut])
def list_agents(_admin: str = Depends(auth.require_admin)):
    return agent_registry.list_agents()


@router.post("/register", response_model=AgentOut)
def register_agent(body: RegisterAgentRequest, _admin: str = Depends(auth.require_admin)):
    agent_registry.register_agent(body.agent_id, body.role, body.allowed_tools)
    return agent_registry.get_agent(body.agent_id)


@router.patch("/{agent_id}/role", response_model=AgentOut)
def change_role(agent_id: str, body: ChangeAgentRoleRequest, admin: str = Depends(auth.require_admin)):
    try:
        agent_registry.change_agent_role(agent_id, body.role, changed_by=admin)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    return agent_registry.get_agent(agent_id)


@router.post("/message", response_model=AgentMessageResponse)
async def send_message(body: AgentMessageRequest, request: Request, admin: str = Depends(auth.require_admin)):
    sender = agent_registry.get_agent(body.sender_agent_id)
    if sender is None or sender["disabled"]:
        # Hard deterministic identity boundary - never reaches the LLM
        # discussion at all, same principle as auth.py rejecting a locked
        # account before gateway.analyze() runs. "Do not automatically
        # trust another agent" (CLAUDE.md 4.5) starts with "does this
        # agent identity even exist and remain active."
        security_db.log_security_event(
            agent_id=body.sender_agent_id, tool_name="agent_message", decision="DENIED_UNKNOWN_OR_DISABLED_AGENT",
            risk="high", detail=f"requested_tool={body.requested_tool}",
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sender agent is not registered or is disabled")

    evidence = gateway.gather_agent_security_evidence(
        body.session_id, body.sender_agent_id, body.requested_tool, body.message_content,
    )
    if body.source_ip:
        evidence["source_ip"] = body.source_ip

    result = await gateway.analyze("agent_security", identity=body.sender_agent_id, evidence=evidence,
                                    sandbox_payload={"kind": "text", "content": body.message_content},
                                    log=request.app.state.log)

    tool_executed = False
    tool_result = None
    tool_denied_reason = None
    if result.action == "ALLOW":
        # agentic_system branch: mcp_gateway.py's TOOL_CATALOG
        # allowed_categories is no longer enforced by authorize_and_execute()
        # (see that function's own docstring) - passing the agent_security
        # discussion is now the only gate before body.requested_tool
        # executes, whatever it names. get_ip_reputation remains the only
        # tool this catalog entry documents as intended for the
        # agent-to-agent path; every other tool_name reaching here is a
        # deliberate, documented regression from main's original
        # category-scoped design, not something this endpoint still stops.
        # This endpoint's only structurally-intended target is
        # get_ip_reputation (see the comment above) - its one argument is
        # built here, from this request's own evidence, the same way
        # every tool's arguments used to be built centrally in
        # mcp_gateway.py::_args_for() before that dispatch table was
        # removed (see mcp_gateway.py's module docstring). A
        # body.requested_tool naming any other tool will reach
        # authorize_and_execute() with this same argument shape and most
        # likely be denied there as invalid arguments, not executed.
        exec_result = mcp_gateway.authorize_and_execute(
            body.requested_tool, "agent_security", body.sender_agent_id,
            {"source_ip": evidence.get("source_ip", "unknown")}, decision_id=result.decision_id,
        )
        if exec_result.status == "authorized_executed":
            tool_executed = True
            tool_result = exec_result.result
        else:
            tool_denied_reason = exec_result.reason or exec_result.status

    return AgentMessageResponse(
        action=result.action, reasoning=result.reasoning, skill_ids=result.skill_ids,
        tool_executed=tool_executed, tool_result=tool_result, tool_denied_reason=tool_denied_reason,
    )
