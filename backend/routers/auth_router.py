"""Login/signup/logout - agentic_system branch.

Password correctness ITSELF is still plain bcrypt (there's no coherent
"agentic" substitute for a one-way cryptographic hash comparison - an
LLM cannot verify a bcrypt hash through reasoning, it doesn't have the
pre-image). Everything downstream of that comparison IS agentic now: the
Security LLM's verdict (security_gateway/gateway.py::analyze(),
unconstrained by floor/ceiling/policy-clamp on this branch) is what
decides whether the account gets locked (webapp_db.py::lock_account()),
replacing main's fixed LOCKOUT_THRESHOLD=3 rule. See
docs/AGENTIC_SYSTEM_EXPERIMENT.md.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status

import auth
import webapp_db as db
from schemas import LoginRequest, LoginResponse, LogoutResponse, MeResponse, SignupRequest
from security_gateway import gateway
from security_gateway.mcp_tools import redis_tool

router = APIRouter(prefix="/api/auth", tags=["auth"])

MIN_PASSWORD_LENGTH = 8


@router.post("/signup", response_model=LoginResponse)
def signup(body: SignupRequest):
    username = body.username.strip()
    email = body.email.strip().lower()

    if not username or not email or not body.password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Username, email, and password are required")
    if len(body.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if db.get_user(username) is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Username already taken")
    if db.get_user_by_email(email) is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already registered")

    # No account is hardcoded/seeded anywhere - the very first account ever
    # created is auto-promoted to admin (otherwise nobody could reach the
    # admin-only Admin Dashboard to promote anyone), every account after
    # that is a plain 'user' until an existing admin changes its role.
    role = "admin" if db.user_count() == 0 else "user"
    db.create_user(username, auth.hash_password(body.password), email=email, role=role)
    token = auth.create_access_token(username)
    return LoginResponse(access_token=token, username=username, role=role)


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request):
    username = body.username
    source_ip = request.client.host if request.client else "unknown"

    if redis_tool.is_blocked(username, "authentication"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                             "Too many suspicious login attempts for this account - try again shortly.")
    # block_ip (security_gateway/mcp_gateway.py) - a source-level block,
    # checked before the account-level one above so it also stops attempts
    # against accounts that haven't individually triggered anything yet.
    if redis_tool.is_blocked(source_ip, "ip_block"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                             "This source has been blocked by the security gateway - try again later.")

    user = db.get_user(username)
    account_exists = user is not None
    locked = bool(user["locked"]) if user else False
    # require_mfa (security_gateway/mcp_gateway.py) - an admin-clearable
    # hold, not a real second-factor challenge (this build has none) -
    # see that tool's docstring for why this scoping is honest rather
    # than a fake MFA flow.
    if user is not None and user.get("mfa_hold"):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                             "This account is on hold pending security review - contact an admin.")

    success = False
    if user is not None and not locked:
        success = auth.verify_password(body.password, user["password_hash"])
    elif user is None:
        # Burn the same bcrypt work a real check would, even though there's
        # no account to check against - both this case and a wrong
        # password on a real account return the identical "Invalid
        # username or password" text below, and now take the same amount
        # of time too, so response timing can't be used to enumerate
        # which usernames are registered. See auth.py::DUMMY_PASSWORD_HASH.
        auth.verify_password(body.password, auth.DUMMY_PASSWORD_HASH)
    evidence = gateway.gather_authentication_evidence(
        username=username, source_ip=source_ip, account_exists=account_exists,
        failed_attempts=(user["failed_attempts"] if user else 0), locked=locked,
        this_attempt_success=success, password=body.password,
    )
    result = await gateway.analyze("authentication", username, evidence, log=request.app.state.log)

    if result.action == "BLOCK":
        # agentic_system branch: the account-level lock is now driven by
        # the Security LLM's own verdict, not a fixed LOCKOUT_THRESHOLD -
        # see webapp_db.py::lock_account()'s docstring.
        if user is not None:
            db.lock_account(username)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                             "Login blocked by the security gateway - suspicious attempt pattern detected.")

    if user is None or locked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                             "Account locked due to too many failed attempts" if locked
                             else "Invalid username or password")

    if not success:
        db.record_failed_login(username)  # evidence only now - never auto-locks, see webapp_db.py
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    db.reset_failed_login(username)
    token = auth.create_access_token(user["username"])
    return LoginResponse(access_token=token, username=user["username"], role=user["role"])


@router.post("/logout", response_model=LogoutResponse)
def logout(token: str = Depends(auth.get_bearer_token), _username: str = Depends(auth.get_current_user)):
    jti = auth.get_token_jti(token)
    if jti is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid token")
    db.revoke_jti(jti)
    return LogoutResponse(revoked=True)


@router.get("/me", response_model=MeResponse)
def me(username: str = Depends(auth.get_current_user)):
    user = db.get_user(username)
    return MeResponse(username=username, role=user["role"] if user else "user")
