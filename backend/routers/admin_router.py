"""Admin-only user management (accounts/roles). Gated on
auth.require_admin (role check), not just auth.get_current_user, since it
mutates other users' access. Security-event/gateway-decision/sandbox
visibility lives in security_router.py instead - this router is scoped to
user administration only.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

import auth
import webapp_db as db
from schemas import SetRoleRequest, UserOut
from security_gateway.mcp_tools import redis_tool

router = APIRouter(prefix="/api/admin", tags=["admin"])

VALID_ROLES = {"admin", "user"}


@router.get("/users", response_model=List[UserOut])
def list_users(_admin: str = Depends(auth.require_admin)):
    return db.list_users()


@router.patch("/users/{username}/role", response_model=UserOut)
def update_role(username: str, body: SetRoleRequest, admin: str = Depends(auth.require_admin)):
    if body.role not in VALID_ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"role must be one of {sorted(VALID_ROLES)}")
    if username == admin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot change your own role")

    target = db.get_user(username)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    db.set_role(username, body.role)
    return db.get_user(username)


@router.post("/users/{username}/clear-mfa-hold", response_model=UserOut)
def clear_mfa_hold(username: str, admin: str = Depends(auth.require_admin)):
    """Clears the hold security_gateway/mcp_gateway.py's require_mfa tool
    sets (skills/authentication/*/SKILL.md's account-takeover response) -
    the only way one is ever lifted, since this build has no real
    second-factor challenge for a user to complete themselves. Returns
    the updated user (same shape as /role and /unlock) so the frontend
    can update its local state the same way for all three actions."""
    target = db.get_user(username)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    db.set_mfa_hold(username, False)
    return db.get_user(username)


@router.post("/users/{username}/unlock", response_model=UserOut)
def unlock_user(username: str, admin: str = Depends(auth.require_admin)):
    """Clears BOTH the account-level lock (webapp_db.LOCKOUT_THRESHOLD -
    3 consecutive failed attempts) AND the AI Security Gateway's own
    identity-level Redis/local block (skills/authentication/brute-force's
    floor - 5+ attempts/1 minute) in one action, since a real SOC "unlock
    this user" request means let them log in again, full stop, regardless
    of which of the two independent mechanisms is currently blocking them
    (see skills/authentication/brute-force/SKILL.md for why they're
    separate). Neither one is ever cleared any other way - a locked
    account can never reach the login success path that would otherwise
    reset it (auth_router.py checks `locked` before verifying the
    password), and a Redis/local block only ever expires on its own TTL."""
    if db.get_user(username) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    db.unlock_account(username)
    redis_tool.unblock_identity(username, "authentication")
    return db.get_user(username)
