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


@router.post("/users/{username}/clear-mfa-hold")
def clear_mfa_hold(username: str, admin: str = Depends(auth.require_admin)):
    """Clears the hold security_gateway/mcp_gateway.py's require_mfa tool
    sets (skills/authentication/*/SKILL.md's account-takeover response) -
    the only way one is ever lifted, since this build has no real
    second-factor challenge for a user to complete themselves."""
    target = db.get_user(username)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    db.set_mfa_hold(username, False)
    return {"username": username, "mfa_hold": False, "cleared_by": admin}
