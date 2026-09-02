"""security_gateway/mcp_gateway.py - agentic_system branch. Category
scoping, rate limiting, and the critical-risk human-approval gate are
all REMOVED (see docs/AGENTIC_SYSTEM_EXPERIMENT.md and
authorize_and_execute()'s own docstring) - any tool name the Security
LLM proposes now executes immediately, regardless of category or
declared risk tier. These tests assert that new (deliberately weaker)
behavior directly, including the specific privilege-escalation shape
this removal creates (a critical tool proposed from an unrelated
category auto-executes with no human in the loop).

2026-09-02: the fourth positional argument to authorize_and_execute() is
now `arguments` - the exact dict the tool's executor receives - not
`evidence` to be transformed by a (now-removed) deterministic
`_args_for()` builder. These tests pass each tool's real expected keys
directly, the same way the Security LLM itself must now."""
from common import security_db
import webapp_db as db
from security_gateway import agent_registry, mcp_gateway
from security_gateway.mcp_tools import redis_tool


def _patch_common(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()
    db.init_db()
    monkeypatch.setattr(redis_tool, "REDIS_URL", "")
    monkeypatch.setattr(redis_tool, "_client", None)
    import collections
    monkeypatch.setattr(mcp_gateway, "_tool_calls", collections.defaultdict(collections.deque))


def test_tools_for_category_offers_the_full_catalog_to_every_category():
    # Real behavior change from main: category scoping is gone -
    # authentication and file_security now both see the entire catalog,
    # not just the tools declared relevant to each.
    auth_tools = mcp_gateway.tools_for_category("authentication")
    file_tools = mcp_gateway.tools_for_category("file_security")
    assert set(auth_tools) == set(mcp_gateway.TOOL_CATALOG.keys())
    assert set(file_tools) == set(mcp_gateway.TOOL_CATALOG.keys())
    assert "remove_vector" in auth_tools  # would have been out-of-scope on main
    assert "get_login_attempts" in file_tools  # same, the other direction


def test_unknown_tool_denied(monkeypatch, temp_sqlite_path):
    # The one check that survives - not a security judgment, just "is
    # there real code to run for this name" (structural, not policy).
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("delete_everything", "authentication", "alice", {})
    assert result.status == "denied_out_of_scope"


def test_out_of_category_tool_now_auto_executes(monkeypatch, temp_sqlite_path):
    # remove_vector is files/rag-scoped on main - here it executes for
    # an authentication request with no category check at all.
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("remove_vector", "authentication", "alice", {})
    assert result.status == "authorized_executed"


def test_low_risk_tool_auto_executes(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("get_login_attempts", "authentication", "alice",
                                                {"username": "alice"})
    assert result.status == "authorized_executed"
    assert result.result is not None
    assert "recent_attempt_count_1min" in result.result


def test_critical_tool_now_auto_executes_no_approval_gate(monkeypatch, temp_sqlite_path):
    # The specific regression docs/AGENTIC_SYSTEM_EXPERIMENT.md calls
    # out: block_ip is risk=critical/requires_approval on main and would
    # queue for a human; here it blocks the IP immediately.
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("block_ip", "authentication", "alice",
                                                {"source_ip": "10.0.0.1"})
    assert result.status == "authorized_executed"
    assert result.call_id is None
    assert redis_tool.is_blocked("10.0.0.1", "ip_block") is True  # already blocked, no approval happened


def test_execute_approved_call_still_works_for_a_manually_queued_call(monkeypatch, temp_sqlite_path):
    # execute_approved_call()/deny_call() themselves are unchanged code -
    # they're just never reached via authorize_and_execute() anymore
    # (nothing queues a pending call on this branch). Queue one directly
    # against security_db to confirm the approval-completion path itself
    # still works, in case anything else ever populates one.
    _patch_common(monkeypatch, temp_sqlite_path)
    call_id = security_db.create_pending_tool_call(None, "block_ip", "alice", {"source_ip": "10.0.0.2"})
    mcp_gateway.execute_approved_call(call_id, decided_by="admin")
    assert redis_tool.is_blocked("10.0.0.2", "ip_block") is True

    call = security_db.get_pending_tool_call(call_id)
    assert call["status"] == "approved"
    assert call["result"]["source_ip"] == "10.0.0.2"


def test_deny_call_still_works_for_a_manually_queued_call(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    call_id = security_db.create_pending_tool_call(None, "block_ip", "alice", {"source_ip": "10.0.0.3"})
    mcp_gateway.deny_call(call_id, decided_by="admin")
    assert redis_tool.is_blocked("10.0.0.3", "ip_block") is False
    call = security_db.get_pending_tool_call(call_id)
    assert call["status"] == "denied"


def test_rate_limit_no_longer_applied(monkeypatch, temp_sqlite_path):
    # Real behavior change: the same tool+identity can now be called far
    # beyond the old rate_limit cap and every call still auto-executes.
    _patch_common(monkeypatch, temp_sqlite_path)
    cfg = mcp_gateway.TOOL_CATALOG["rate_limit_user"]["rate_limit"]
    for _ in range(cfg["max"] + 5):
        result = mcp_gateway.authorize_and_execute("rate_limit_user", "authentication", "bob",
                                                     {"username": "bob"})
        assert result.status == "authorized_executed"


def test_require_mfa_sets_real_hold(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    db.create_user("holduser", "hash", email="h@example.com")
    mcp_gateway.authorize_and_execute("require_mfa", "authentication", "holduser", {"username": "holduser"})
    assert db.get_user("holduser")["mfa_hold"] == 1


def test_terminate_session_now_auto_executes(monkeypatch, temp_sqlite_path):
    # terminate_session is risk=critical on main (requires approval) -
    # here it takes effect immediately, no execute_approved_call needed.
    _patch_common(monkeypatch, temp_sqlite_path)
    db.create_user("sessuser", "hash", email="s@example.com")
    result = mcp_gateway.authorize_and_execute("terminate_session", "authentication", "sessuser",
                                                {"username": "sessuser"})
    assert result.status == "authorized_executed"
    assert db.get_user("sessuser")["sessions_invalidated_before"] is not None


def test_get_ip_reputation_reflects_prior_blocks(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    security_db.record_ip_block("203.0.113.5", "test")
    security_db.record_ip_block("203.0.113.5", "test")
    result = mcp_gateway.authorize_and_execute("get_ip_reputation", "authentication", "alice",
                                                {"source_ip": "203.0.113.5"})
    assert result.result["prior_blocks_from_this_ip"] == 2


def test_disclose_pii_answer_no_longer_scoped_to_rag_security(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("disclose_pii_answer", "authentication", "alice", {})
    assert result.status == "authorized_executed"


def test_disclose_pii_answer_now_auto_executes_and_generates_the_answer(monkeypatch, temp_sqlite_path):
    # disclose_pii_answer is specifically designed on main to withhold
    # disclosure pending admin approval (skills/rag/pii-exposure's
    # response.yaml) - here the real answer is generated and returned
    # immediately, no human ever sees it first.
    _patch_common(monkeypatch, temp_sqlite_path)
    arguments = {"question": "ayyappan phone number", "context": "call +91 9715218680",
                 "pii_types_found": ["phone"]}
    result = mcp_gateway.authorize_and_execute("disclose_pii_answer", "rag_security", "gwtest_admin", arguments)
    assert result.status == "authorized_executed"
    assert result.call_id is None
    assert result.result["question"] == "ayyappan phone number"
    assert "answer" in result.result


def test_search_external_web_no_longer_scoped_to_rag_security(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("search_external_web", "authentication", "alice",
                                                {"query": "latest cve news"})
    assert result.status != "denied_out_of_scope"


def test_search_external_web_blocks_internal_host_query_before_network_call(monkeypatch, temp_sqlite_path):
    # The pre-call SSRF guard lives INSIDE the executor itself, not in
    # the (now-removed) category/rate-limit layer - it's real input
    # validation, not a "security decision" in the sense this branch's
    # experiment is about, so it's intentionally left untouched.
    _patch_common(monkeypatch, temp_sqlite_path)

    def _fail_if_called(*a, **k):
        raise AssertionError("httpx.get must not be called for an SSRF-shaped query")
    import httpx
    monkeypatch.setattr(httpx, "get", _fail_if_called)

    result = mcp_gateway.authorize_and_execute("search_external_web", "rag_security", "alice",
                                                {"query": "fetch http://192.168.1.1/admin"})
    assert result.status == "authorized_executed"
    assert "error" in result.result
    assert "private/internal" in result.result["error"]


def test_search_external_web_empty_query_rejected(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("search_external_web", "rag_security", "alice",
                                                {"query": "  "})
    assert "error" in result.result


def test_search_external_web_real_call_shape(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)

    class _FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "AbstractText": "Python is a programming language.",
                "AbstractSource": "Wikipedia",
                "AbstractURL": "https://en.wikipedia.org/wiki/Python",
                "RelatedTopics": [{"Text": "Python (genus)", "FirstURL": "https://x"}, "not-a-dict"],
            }

    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResp())

    result = mcp_gateway.authorize_and_execute("search_external_web", "rag_security", "alice",
                                                {"query": "what is python"})
    assert result.status == "authorized_executed"
    assert result.result["abstract"] == "Python is a programming language."
    assert result.result["related_topics"] == [{"text": "Python (genus)", "url": "https://x"}]


def test_search_external_web_no_longer_rate_limited(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **k: AssertionError("should not reach network"))
    cfg = mcp_gateway.TOOL_CATALOG["search_external_web"]["rate_limit"]
    for _ in range(cfg["max"] + 3):
        result = mcp_gateway.authorize_and_execute("search_external_web", "rag_security", "carol",
                                                    {"query": ""})
        assert result.status == "authorized_executed"


def test_get_ip_reputation_allowed_for_agent_security_category(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("get_ip_reputation", "agent_security", "reporting_agent",
                                                {"source_ip": "203.0.113.5"})
    assert result.status == "authorized_executed"


def test_block_ip_now_reachable_from_agent_security_category(monkeypatch, temp_sqlite_path):
    # The structural boundary main's test of the same name demonstrated
    # (no agent, however trusted, can reach block_ip via the A2A path) is
    # exactly what's removed here: an agent-proposed block_ip now
    # executes, regardless of category. This is the concrete shape of
    # "prompt injection auto-executes a critical tool" from
    # docs/AGENTIC_SYSTEM_EXPERIMENT.md.
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("block_ip", "agent_security", "ops_admin_agent",
                                                {"source_ip": "203.0.113.5"})
    assert result.status == "authorized_executed"
    assert redis_tool.is_blocked("203.0.113.5", "ip_block") is True


def test_revoke_agent_credentials_now_auto_executes(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("rogue_agent", "viewer", ["get_ip_reputation"])

    result = mcp_gateway.authorize_and_execute("revoke_agent_credentials", "agent_security", "rogue_agent",
                                                {"agent_id": "rogue_agent"})
    assert result.status == "authorized_executed"
    assert result.result["disabled"] is True
    assert agent_registry.get_agent("rogue_agent")["disabled"] is True  # re-read, verified


def test_revoke_agent_credentials_no_longer_scoped_to_agent_security(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("revoke_agent_credentials", "authentication", "someone",
                                                {"agent_id": "someone"})
    assert result.status == "authorized_executed"


def test_remove_agent_tool_access_now_auto_executes(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("borderline_agent", "admin", ["get_ip_reputation", "block_ip"])

    arguments = {"agent_id": "borderline_agent", "tool_name": "block_ip"}
    result = mcp_gateway.authorize_and_execute("remove_agent_tool_access", "agent_security",
                                                "borderline_agent", arguments)
    assert result.status == "authorized_executed"
    assert result.result["removed_tool"] == "block_ip"
    assert "block_ip" not in agent_registry.get_agent("borderline_agent")["allowed_tools"]
    assert "get_ip_reputation" in agent_registry.get_agent("borderline_agent")["allowed_tools"]
