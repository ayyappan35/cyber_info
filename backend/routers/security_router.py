"""Read/admin surface over the security gateway's own state: the SIEM
event log, the gateway decision history, the sandbox (quarantine) store,
and the Redis/local block list - the architecture diagram's MCP Tools box,
made visible to the Admin Dashboard.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

import auth
from common import security_db
from schemas import SetLlmProviderRequest
from security_gateway import chain_detection, mcp_gateway, runtime_config
from security_gateway.mcp_tools import redis_tool, sandbox_tool

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/events")
def list_security_events(limit: int = 50, _admin: str = Depends(auth.require_admin)):
    return security_db.list_security_events(limit=limit)


@router.get("/decisions")
def list_gateway_decisions(limit: int = 50, category: Optional[str] = None,
                            _admin: str = Depends(auth.require_admin)):
    return security_db.list_gateway_decisions(limit=limit, category=category)


@router.get("/sandbox")
def list_sandbox(released: bool = False, _admin: str = Depends(auth.require_admin)):
    return sandbox_tool.list_sandboxed(released=released)


@router.post("/sandbox/{sandbox_id}/release")
def release_sandbox_item(sandbox_id: str, admin: str = Depends(auth.require_admin)):
    if not sandbox_tool.release(sandbox_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sandbox item not found")
    security_db.log_security_event(agent_id=admin, tool_name="release_sandbox_item",
                                    decision="released", detail=sandbox_id)
    return {"sandbox_id": sandbox_id, "released": True}


@router.get("/blocked")
def list_blocked_identities(_admin: str = Depends(auth.require_admin)):
    return redis_tool.list_blocked()


@router.get("/tool-calls")
def list_tool_calls(status: Optional[str] = "pending", _admin: str = Depends(auth.require_admin)):
    return security_db.list_tool_calls(status=status)


@router.post("/tool-calls/{call_id}/approve")
def approve_tool_call(call_id: int, admin: str = Depends(auth.require_admin)):
    try:
        result = mcp_gateway.execute_approved_call(call_id, decided_by=admin)
    except ValueError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    return {"call_id": call_id, "status": "approved", "result": result}


@router.post("/tool-calls/{call_id}/deny")
def deny_tool_call(call_id: int, admin: str = Depends(auth.require_admin)):
    try:
        mcp_gateway.deny_call(call_id, decided_by=admin)
    except ValueError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    return {"call_id": call_id, "status": "denied"}


@router.get("/chain/{identity}")
def get_chain(identity: str, _admin: str = Depends(auth.require_admin)):
    return chain_detection.detect_chain(identity)


@router.get("/llm-config")
def get_llm_config(_username: str = Depends(auth.get_current_user)):
    """Any authenticated user can read the active provider/model - the
    chat UI displays this - but only an admin can change it (below)."""
    return runtime_config.status()


@router.post("/llm-config")
def set_llm_config(body: SetLlmProviderRequest, admin: str = Depends(auth.require_admin)):
    try:
        runtime_config.set_active_provider(body.provider)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    security_db.log_security_event(agent_id=admin, tool_name="set_llm_provider",
                                    decision="changed", detail=f"provider={body.provider}")
    return runtime_config.status()
