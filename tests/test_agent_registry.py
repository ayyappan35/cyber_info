"""Tests for security_gateway/agent_registry.py - the real registry
skills/agents/tool-abuse and .../privilege-escalation check against."""
from common import security_db
from security_gateway import agent_registry


def _patch(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()


def test_register_and_get_agent(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("test_agent", "viewer", ["get_ip_reputation"])
    agent = agent_registry.get_agent("test_agent")
    assert agent["role"] == "viewer"
    assert agent["allowed_tools"] == ["get_ip_reputation"]
    assert agent["disabled"] is False


def test_get_unregistered_agent_returns_none(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    assert agent_registry.get_agent("nobody") is None


def test_register_is_idempotent_upsert(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("test_agent", "viewer", ["get_ip_reputation"])
    agent_registry.register_agent("test_agent", "operator", ["get_ip_reputation", "rate_limit_user"])
    agent = agent_registry.get_agent("test_agent")
    assert agent["role"] == "operator"
    assert agent["allowed_tools"] == ["get_ip_reputation", "rate_limit_user"]


def test_seed_default_agents_creates_expected_rows(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.seed_default_agents()
    reporting = agent_registry.get_agent("reporting_agent")
    ops = agent_registry.get_agent("ops_admin_agent")
    assert reporting["allowed_tools"] == ["get_ip_reputation"]
    assert "block_ip" in ops["allowed_tools"]


def test_seed_default_agents_does_not_overwrite_existing(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("reporting_agent", "admin", ["block_ip"])  # manually promoted
    agent_registry.seed_default_agents()
    assert agent_registry.get_agent("reporting_agent")["role"] == "admin"  # seed did not clobber it


def test_disable_agent(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("test_agent", "viewer", ["get_ip_reputation"])
    agent_registry.disable_agent("test_agent")
    assert agent_registry.get_agent("test_agent")["disabled"] is True


def test_remove_tool_access(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("test_agent", "admin", ["get_ip_reputation", "block_ip"])
    result = agent_registry.remove_tool_access("test_agent", "block_ip")
    assert result["allowed_tools"] == ["get_ip_reputation"]


def test_remove_tool_access_unknown_agent_raises(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    import pytest
    with pytest.raises(ValueError):
        agent_registry.remove_tool_access("nobody", "block_ip")


def test_change_agent_role_records_audit_event(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("test_agent", "viewer", [])
    updated = agent_registry.change_agent_role("test_agent", "admin", changed_by="human_admin")
    assert updated["role"] == "admin"


def test_change_agent_role_unknown_agent_raises(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    import pytest
    with pytest.raises(ValueError):
        agent_registry.change_agent_role("nobody", "admin", changed_by="human_admin")


def test_session_start_role_recorded_once_and_immutable(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("test_agent", "viewer", [])
    first = agent_registry.session_start_role("sess-1", "test_agent", "viewer")
    assert first["role_at_session_start"] == "viewer"

    # Even if called again with a different "current_role" (e.g. the agent's
    # role changed later in the same session), the recorded session-start
    # value must not change - that's the whole point of the signal.
    second = agent_registry.session_start_role("sess-1", "test_agent", "admin")
    assert second["role_at_session_start"] == "viewer"


def test_role_change_event_id_since_none_when_no_change(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("test_agent", "viewer", [])
    assert agent_registry.role_change_event_id_since("test_agent", "2000-01-01T00:00:00") is None


def test_role_change_event_id_since_found_after_change(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("test_agent", "viewer", [])
    before = "2000-01-01T00:00:00"
    agent_registry.change_agent_role("test_agent", "admin", changed_by="human_admin")
    event_id = agent_registry.role_change_event_id_since("test_agent", before)
    assert event_id is not None


def test_list_agents(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("a1", "viewer", [])
    agent_registry.register_agent("a2", "admin", [])
    agents = agent_registry.list_agents()
    assert {a["agent_id"] for a in agents} == {"a1", "a2"}
