from common import security_db
from security_gateway.mcp_tools import redis_tool


def test_fallback_backend_when_no_redis_url(monkeypatch):
    monkeypatch.setattr(redis_tool, "REDIS_URL", "")
    monkeypatch.setattr(redis_tool, "_client", None)
    monkeypatch.setattr(redis_tool, "_redis_unavailable", False)
    assert redis_tool.backend() == "sqlite-fallback"


def test_block_and_is_blocked(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    monkeypatch.setattr(redis_tool, "REDIS_URL", "")
    monkeypatch.setattr(redis_tool, "_client", None)
    security_db.init_db()

    assert redis_tool.is_blocked("eve", "authentication") is False
    redis_tool.block_identity("eve", "authentication", "brute force pattern", ttl_seconds=900)
    assert redis_tool.is_blocked("eve", "authentication") is True
    assert any(b["identity"] == "eve" for b in redis_tool.list_blocked())


def test_unblock_identity_clears_the_block(monkeypatch, temp_sqlite_path):
    # Admin "unlock this user" action (backend/routers/admin_router.py) -
    # a block otherwise only ever expires on its own TTL.
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    monkeypatch.setattr(redis_tool, "REDIS_URL", "")
    monkeypatch.setattr(redis_tool, "_client", None)
    security_db.init_db()

    redis_tool.block_identity("frank", "authentication", "brute force pattern", ttl_seconds=900)
    assert redis_tool.is_blocked("frank", "authentication") is True

    removed = redis_tool.unblock_identity("frank", "authentication")
    assert removed is True
    assert redis_tool.is_blocked("frank", "authentication") is False


def test_unblock_identity_nothing_blocked_returns_false(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    monkeypatch.setattr(redis_tool, "REDIS_URL", "")
    monkeypatch.setattr(redis_tool, "_client", None)
    security_db.init_db()

    assert redis_tool.unblock_identity("nobody", "authentication") is False


def test_attempt_count_sliding_window(monkeypatch):
    monkeypatch.setattr(redis_tool, "_attempts", {})
    import collections
    redis_tool._attempts = collections.defaultdict(collections.deque)

    identity = "frank"
    assert redis_tool.get_attempt_count(identity) == 0
    redis_tool.record_attempt(identity)
    redis_tool.record_attempt(identity)
    redis_tool.record_attempt(identity)
    assert redis_tool.get_attempt_count(identity, window_seconds=300) == 3


def test_attempt_count_expires_outside_window(monkeypatch):
    import collections
    import time
    redis_tool._attempts = collections.defaultdict(collections.deque)

    identity = "grace"
    redis_tool._attempts[identity].append(time.time() - 1000)  # old, outside a 300s window
    assert redis_tool.get_attempt_count(identity, window_seconds=300) == 0


# --- credential-enumeration: nonexistent-account attempts per source ----

def test_nonexistent_attempt_count_tracks_per_source(monkeypatch):
    import collections
    redis_tool._nonexistent_attempts = collections.defaultdict(collections.deque)

    source_ip = "198.51.100.50"
    assert redis_tool.get_nonexistent_attempt_count(source_ip) == 0
    redis_tool.record_nonexistent_attempt(source_ip, "ghost1")
    redis_tool.record_nonexistent_attempt(source_ip, "ghost2")
    assert redis_tool.get_nonexistent_attempt_count(source_ip) == 2
    # A different source's attempts don't bleed into this one's count.
    assert redis_tool.get_nonexistent_attempt_count("198.51.100.51") == 0


def test_nonexistent_attempt_count_expires_outside_window(monkeypatch):
    import collections
    import time
    redis_tool._nonexistent_attempts = collections.defaultdict(collections.deque)

    source_ip = "198.51.100.52"
    redis_tool._nonexistent_attempts[source_ip].append((time.time() - 1000, "ghost"))
    assert redis_tool.get_nonexistent_attempt_count(source_ip, window_seconds=300) == 0


# --- impossible-travel: distinct source IPs per account -----------------

def test_distinct_source_ips_for_account_counts_unique_ips(monkeypatch):
    import collections
    redis_tool._account_source_ips = collections.defaultdict(collections.deque)

    username = "nomad"
    assert redis_tool.get_distinct_source_ips_for_account(username) == 0
    redis_tool.record_account_source_ip(username, "203.0.113.1")
    redis_tool.record_account_source_ip(username, "203.0.113.1")  # same IP again - not a new distinct value
    redis_tool.record_account_source_ip(username, "203.0.113.99")
    assert redis_tool.get_distinct_source_ips_for_account(username) == 2


def test_distinct_source_ips_for_account_expires_outside_window(monkeypatch):
    import collections
    import time
    redis_tool._account_source_ips = collections.defaultdict(collections.deque)

    username = "stale_nomad"
    redis_tool._account_source_ips[username].append((time.time() - 2000, "203.0.113.5"))
    assert redis_tool.get_distinct_source_ips_for_account(username, window_seconds=900) == 0


# --- mfa-fatigue: MFA challenge presentation count -----------------------

def test_mfa_challenge_count_tracks_and_expires(monkeypatch):
    import collections
    import time
    redis_tool._mfa_challenge_events = collections.defaultdict(collections.deque)

    username = "held_user"
    assert redis_tool.get_mfa_challenge_count(username) == 0
    redis_tool.record_mfa_challenge(username)
    redis_tool.record_mfa_challenge(username)
    assert redis_tool.get_mfa_challenge_count(username) == 2

    redis_tool._mfa_challenge_events[username].appendleft(time.time() - 5000)
    assert redis_tool.get_mfa_challenge_count(username, window_seconds=600) == 2  # the old one is popped from the left
