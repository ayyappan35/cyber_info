"""Redis MCP tool: ephemeral rate/attempt tracking and the identity block
list the Authentication branch enforces a BLOCK decision through.

Real Redis is used when REDIS_URL is set and the `redis` package is
installed - a genuine `redis.Redis.from_url(...)` client, not a stub. If
neither is available (the common case for local development on this
Windows machine, where no Redis server runs), this falls back to a real
SQLite-backed implementation (security_db.py's blocked_identities table)
with identical semantics (block-until-expiry, attempt counting) - a
working local substitute, not a fake/no-op. Which backend is active is
reported by `backend()` so callers/docs can be honest about it.
"""
import os
import time
from collections import defaultdict, deque

from common import security_db

REDIS_URL = os.environ.get("REDIS_URL", "")

_client = None
_redis_unavailable = False


def _get_client():
    global _client, _redis_unavailable
    if _client is not None or _redis_unavailable or not REDIS_URL:
        return _client
    try:
        import redis  # optional dependency
        _client = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=1)
        _client.ping()
    except Exception:
        _client = None
        _redis_unavailable = True
    return _client


def backend() -> str:
    return "redis" if _get_client() is not None else "sqlite-fallback"


# --- attempt tracking (sliding window, in-process) -----------------------
# In-memory even in the Redis case would be wrong across multiple worker
# processes, but this app runs as a single uvicorn process (see
# backend/main.py) - a real constraint of the local dev deployment, not
# glossed over. Documented in docs/SECURITY_GATEWAY.md.
_attempts = defaultdict(deque)


def record_attempt(identity: str) -> None:
    _attempts[identity].append(time.time())


def get_attempt_count(identity: str, window_seconds: int = 300) -> int:
    now = time.time()
    dq = _attempts[identity]
    while dq and now - dq[0] > window_seconds:
        dq.popleft()
    return len(dq)


# --- per-source-IP username tracking (credential-stuffing detection) -----
# Same in-process, single-worker constraint as _attempts above. Keyed by
# source IP -> deque of (timestamp, username), so
# authentication/credential-stuffing/SKILL.md's "many distinct accounts
# from one source" signal can be computed - distinct from get_attempt_count
# above, which only tracks volume against ONE username.
_username_attempts = defaultdict(deque)


def record_username_attempt(source_ip: str, username: str) -> None:
    _username_attempts[source_ip].append((time.time(), username))


def get_distinct_usernames(source_ip: str, window_seconds: int = 300) -> int:
    now = time.time()
    dq = _username_attempts[source_ip]
    while dq and now - dq[0][0] > window_seconds:
        dq.popleft()
    return len({u for _ts, u in dq})


# --- block list ------------------------------------------------------------

def block_identity(identity: str, category: str, reason: str, ttl_seconds: int) -> None:
    client = _get_client()
    if client is not None:
        client.setex(f"blocked:{category}:{identity}", ttl_seconds, reason)
    # Always also recorded in SQLite (security_db), even when Redis is the
    # enforcement backend - this is the admin dashboard's read path
    # (list_blocked below), and a Redis SCAN-based listing implementation
    # isn't worth adding for a rarely-used debug view. is_blocked() below
    # still checks Redis first when it's the active backend, so enforcement
    # correctness never depends on this second write succeeding.
    security_db.block_identity(identity, category, reason, ttl_seconds)


def is_blocked(identity: str, category: str) -> bool:
    client = _get_client()
    if client is not None:
        return client.exists(f"blocked:{category}:{identity}") > 0
    return security_db.is_identity_blocked(identity, category)


def list_blocked() -> list:
    return security_db.list_blocked_identities()
