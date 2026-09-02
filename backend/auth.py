"""Password hashing + JWT issuing/verification for the web app's own login,
plus a bearer-token dependency for protected routes.
"""
import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import webapp_db as db

SECRET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jwt_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12h, generous for a demo session

_bearer = HTTPBearer(auto_error=False)


def _get_or_create_secret() -> str:
    env_secret = os.environ.get("JWT_SECRET")
    if env_secret:
        return env_secret
    if os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    secret = secrets.token_hex(32)
    with open(SECRET_PATH, "w", encoding="utf-8") as f:
        f.write(secret)
    return secret


SECRET_KEY = _get_or_create_secret()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


# Username-enumeration timing fix: a real bcrypt check is deliberately
# slow (that's the point of bcrypt), so a login attempt against a
# username that doesn't exist - which never reaches verify_password()
# at all - responds measurably FASTER than one against a real username
# with a wrong password, even though both return the exact same
# "Invalid username or password" text (auth_router.py). That timing gap
# is itself an enumeration side-channel. DUMMY_PASSWORD_HASH is a real
# bcrypt hash (same cost factor as every real one, via hash_password())
# of a random value nobody will ever type - auth_router.py runs
# verify_password() against it for a nonexistent username, burning the
# same CPU work a real check would, purely so response timing carries no
# signal either way. Generated once per process at import time (not
# persisted, not tied to any account) - a fresh value each restart is
# fine since it's never meant to match anything.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_hex(32))


def create_access_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire, "iat": now, "jti": secrets.token_hex(16)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_token_jti(token: str):
    """Extract the jti claim even from an expired token, so an old token can
    still be explicitly revoked on logout rather than just left to expire."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
    except jwt.InvalidTokenError:
        return None
    return payload.get("jti")


def init_users():
    """No hardcoded accounts - every user comes from signup and lives only in
    the DB. Just makes sure the schema exists on startup."""
    db.init_db()


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> str:
    """Runs on every protected request. Deliberately a direct, synchronous
    check - not an MCP tool call - since this is hot-path request middleware,
    not a user-triggered action like login/logout (see webapp_auth_mcp.py).
    The revocation lookup keeps it honest with logout: a revoked token is
    rejected here even though the JWT signature itself is still valid."""
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")

    username = payload.get("sub")
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")

    if payload.get("jti") and db.is_jti_revoked(payload["jti"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token has been revoked")

    # security_gateway's terminate_session MCP tool (mcp_gateway.py) sets
    # this cutoff - any token issued before it is rejected even though its
    # signature and per-jti revocation status are both still valid. This
    # is the real "log out everywhere" mechanism (CLAUDE.md: no fake
    # implementations) - stateless JWTs have no session list to revoke
    # individually, so a cutoff timestamp is the honest equivalent.
    user = db.get_user(username)
    cutoff = user.get("sessions_invalidated_before") if user else None
    if cutoff and payload.get("iat"):
        # Both sides formatted identically (timespec="seconds") before the
        # string comparison - ISO-8601 UTC timestamps compare correctly
        # lexicographically only when their precision/format match exactly.
        issued_at = datetime.fromtimestamp(payload["iat"], tz=timezone.utc).isoformat(timespec="seconds")
        if issued_at < cutoff:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session terminated - please log in again")

    return username


def get_bearer_token(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> str:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return creds.credentials


def require_admin(username: str = Depends(get_current_user)) -> str:
    """Same identity check as get_current_user, plus a role check for routes
    that mutate shared state (e.g. the knowledge-base upload endpoint) rather
    than a user's own data."""
    user = db.get_user(username)
    if user is None or user.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    return username
