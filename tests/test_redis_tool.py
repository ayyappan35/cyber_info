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
