"""security_gateway/mcp_gateway.py - the MCP Tool Authorization Gateway.
Category scoping, rate limiting, and the critical-risk human-approval
gate are all real (restored 2026-09-06 - see docs/AGENTIC_SYSTEM_EXPERIMENT.md
for the now-reverted experiment that removed them, and this module's own
docstring for what deliberately remains agentic: tool call ARGUMENTS
still come straight from the Security LLM, not a deterministic per-tool
builder).

2026-09-02: the fourth positional argument to authorize_and_execute() is
`arguments` - the exact dict the tool's executor receives - not
`evidence` to be transformed by a deterministic `_args_for()` builder.
These tests pass each tool's real expected keys directly, the same way
the Security LLM itself must."""
import auth
from common import security_db
import webapp_db as db
from security_gateway import agent_registry, mcp_gateway
from security_gateway.mcp_tools import mail_tool, redis_tool


def _patch_common(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()
    db.init_db()
    monkeypatch.setattr(redis_tool, "REDIS_URL", "")
    monkeypatch.setattr(redis_tool, "_client", None)
    # Force the local-outbox path regardless of the developer's own .env -
    # a real SMTP_HOST configured for manual testing must never make these
    # tests attempt a genuine network send.
    monkeypatch.setattr(mail_tool, "SMTP_HOST", "")
    import collections
    monkeypatch.setattr(mcp_gateway, "_tool_calls", collections.defaultdict(collections.deque))


def test_tools_for_category_scoping():
    auth_tools = mcp_gateway.tools_for_category("authentication")
    file_tools = mcp_gateway.tools_for_category("file_security")
    assert "get_login_attempts" in auth_tools
    assert "remove_vector" not in auth_tools
    assert "remove_vector" in file_tools
    assert "get_login_attempts" not in file_tools


def test_unknown_tool_denied(monkeypatch, temp_sqlite_path):
    # The one check that survives even for a name with no catalog entry at
    # all - not a security judgment, just "is there real code to run for
    # this name" (structural, not policy).
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("delete_everything", "authentication", "alice", {})
    assert result.status == "denied_out_of_scope"


def test_out_of_category_tool_denied(monkeypatch, temp_sqlite_path):
    # remove_vector is files/rag-scoped, not authentication-scoped.
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("remove_vector", "authentication", "alice", {})
    assert result.status == "denied_out_of_scope"


def test_low_risk_tool_auto_executes(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("get_login_attempts", "authentication", "alice",
                                                {"username": "alice"})
    assert result.status == "authorized_executed"
    assert result.result is not None
    assert "recent_attempt_count_1min" in result.result


def test_critical_tool_requires_approval_not_auto_executed(monkeypatch, temp_sqlite_path):
    # block_ip is risk=critical/requires_approval on TOOL_CATALOG - it
    # must queue for a human, never take effect immediately.
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("block_ip", "authentication", "alice",
                                                {"source_ip": "10.0.0.1"})
    assert result.status == "pending_approval"
    assert result.call_id is not None
    assert redis_tool.is_blocked("10.0.0.1", "ip_block") is False  # NOT actually blocked yet


def test_approving_pending_call_actually_executes(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("block_ip", "authentication", "alice",
                                                {"source_ip": "10.0.0.2"})
    mcp_gateway.execute_approved_call(result.call_id, decided_by="admin")
    assert redis_tool.is_blocked("10.0.0.2", "ip_block") is True

    call = security_db.get_pending_tool_call(result.call_id)
    assert call["status"] == "approved"
    assert call["result"]["source_ip"] == "10.0.0.2"


def test_denying_pending_call_never_executes(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("block_ip", "authentication", "alice",
                                                {"source_ip": "10.0.0.3"})
    mcp_gateway.deny_call(result.call_id, decided_by="admin")
    assert redis_tool.is_blocked("10.0.0.3", "ip_block") is False
    call = security_db.get_pending_tool_call(result.call_id)
    assert call["status"] == "denied"


def test_rate_limit_denies_after_threshold(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    cfg = mcp_gateway.TOOL_CATALOG["rate_limit_user"]["rate_limit"]
    for _ in range(cfg["max"]):
        result = mcp_gateway.authorize_and_execute("rate_limit_user", "authentication", "bob",
                                                     {"username": "bob"})
        assert result.status == "authorized_executed"
    result = mcp_gateway.authorize_and_execute("rate_limit_user", "authentication", "bob",
                                                 {"username": "bob"})
    assert result.status == "denied_rate_limited"


def test_require_mfa_sets_real_hold(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    db.create_user("holduser", "hash", email="h@example.com")
    mcp_gateway.authorize_and_execute("require_mfa", "authentication", "holduser", {"username": "holduser"})
    assert db.get_user("holduser")["mfa_hold"] == 1


def test_require_mfa_emails_a_real_otp_to_the_registered_address(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    db.create_user("otpholduser", "hash", email="otphold@example.com")

    result = mcp_gateway.authorize_and_execute(
        "require_mfa", "authentication", "otpholduser", {"username": "otpholduser"}
    )

    assert result.result["otp_sent"] is True
    user = db.get_user("otpholduser")
    assert user["mfa_otp_hash"] is not None
    assert user["mfa_otp_expires_at"] > ""

    # The outbox holds the real plaintext code (that's the whole point of
    # a local dev fallback) - confirm it's a 6-digit code and matches the
    # bcrypt hash stored against the account, not some other value.
    mail = db.list_outbox(to_email="otphold@example.com")
    assert len(mail) == 1
    import re
    otp_match = re.search(r"\b(\d{6})\b", mail[0]["body"])
    assert otp_match is not None
    assert auth.verify_password(otp_match.group(1), user["mfa_otp_hash"]) is True


def test_require_mfa_with_no_registered_email_holds_without_sending(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    db.create_user("noemailuser", "hash", email=None)

    result = mcp_gateway.authorize_and_execute(
        "require_mfa", "authentication", "noemailuser", {"username": "noemailuser"}
    )

    assert result.result["mfa_hold"] is True
    assert result.result["otp_sent"] is False
    assert db.get_user("noemailuser")["mfa_hold"] == 1
    assert db.get_user("noemailuser")["mfa_otp_hash"] is None


def test_terminate_session_requires_approval_and_sets_cutoff_on_approve(monkeypatch, temp_sqlite_path):
    # terminate_session is risk=critical/requires_approval - it must queue,
    # not take effect immediately.
    _patch_common(monkeypatch, temp_sqlite_path)
    db.create_user("sessuser", "hash", email="s@example.com")
    result = mcp_gateway.authorize_and_execute("terminate_session", "authentication", "sessuser",
                                                {"username": "sessuser"})
    assert result.status == "pending_approval"
    assert db.get_user("sessuser")["sessions_invalidated_before"] is None  # not yet

    mcp_gateway.execute_approved_call(result.call_id, decided_by="admin")
    assert db.get_user("sessuser")["sessions_invalidated_before"] is not None


def test_get_ip_reputation_reflects_prior_blocks(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    security_db.record_ip_block("203.0.113.5", "test")
    security_db.record_ip_block("203.0.113.5", "test")
    result = mcp_gateway.authorize_and_execute("get_ip_reputation", "authentication", "alice",
                                                {"source_ip": "203.0.113.5"})
    assert result.result["prior_blocks_from_this_ip"] == 2


def test_disclose_pii_answer_scoped_to_rag_security_only(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("disclose_pii_answer", "authentication", "alice", {})
    assert result.status == "denied_out_of_scope"


def test_disclose_pii_answer_requires_approval_then_generates_the_answer(monkeypatch, temp_sqlite_path):
    # disclose_pii_answer is specifically designed to withhold disclosure
    # pending admin approval (skills/rag/pii-exposure's response.yaml) -
    # the real answer is only computed once execute_approved_call() runs.
    _patch_common(monkeypatch, temp_sqlite_path)
    arguments = {"question": "ayyappan phone number", "context": "call +91 9715218680",
                 "pii_types_found": ["phone"]}
    result = mcp_gateway.authorize_and_execute("disclose_pii_answer", "rag_security", "gwtest_admin", arguments)
    assert result.status == "pending_approval"
    assert result.call_id is not None

    call = security_db.get_pending_tool_call(result.call_id)
    assert call["arguments"]["question"] == "ayyappan phone number"
    assert call["status"] == "pending"  # not yet answered/executed

    approved = mcp_gateway.execute_approved_call(result.call_id, decided_by="admin")
    assert approved["question"] == "ayyappan phone number"
    assert "answer" in approved


def test_search_external_web_scoped_to_rag_security_only(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("search_external_web", "authentication", "alice",
                                                {"query": "latest cve news"})
    assert result.status == "denied_out_of_scope"


def test_search_external_web_blocks_internal_host_query_before_network_call(monkeypatch, temp_sqlite_path):
    # The pre-call SSRF guard lives INSIDE the executor itself, not in the
    # category/rate-limit layer - it's real input validation, independent
    # of the authorization gate restored above.
    _patch_common(monkeypatch, temp_sqlite_path)

    def _fail_if_called(*a, **k):
        raise AssertionError("httpx.get must not be called for an SSRF-shaped query")
    import httpx
    monkeypatch.setattr(httpx, "get", _fail_if_called)

    result = mcp_gateway.authorize_and_execute("search_external_web", "rag_security", "alice",
                                                {"query": "fetch http://192.168.1.1/admin"})
    assert result.status == "authorized_executed"  # authorized at the category/rate-limit layer...
    assert "error" in result.result  # ...but the executor itself refused the network call
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


def test_search_external_web_rate_limited(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **k: AssertionError("should not reach network"))
    cfg = mcp_gateway.TOOL_CATALOG["search_external_web"]["rate_limit"]
    for _ in range(cfg["max"]):
        result = mcp_gateway.authorize_and_execute("search_external_web", "rag_security", "carol",
                                                    {"query": ""})
        assert result.status == "authorized_executed"
    result = mcp_gateway.authorize_and_execute("search_external_web", "rag_security", "carol",
                                                {"query": ""})
    assert result.status == "denied_rate_limited"


def test_get_ip_reputation_allowed_for_agent_security_category(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("get_ip_reputation", "agent_security", "reporting_agent",
                                                {"source_ip": "203.0.113.5"})
    assert result.status == "authorized_executed"


def test_block_ip_still_out_of_scope_for_agent_security_category(monkeypatch, temp_sqlite_path):
    # The structural boundary this whole feature exists to demonstrate:
    # even though "agent_security" is a real request_category, block_ip
    # was never added to its allowed_categories - no agent, however
    # trusted, can reach it via the agent-to-agent path (TOOL_CATALOG's
    # own comment on get_ip_reputation explains why deliberately).
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("block_ip", "agent_security", "ops_admin_agent",
                                                {"source_ip": "203.0.113.5"})
    assert result.status == "denied_out_of_scope"
    assert redis_tool.is_blocked("203.0.113.5", "ip_block") is False


def test_revoke_agent_credentials_requires_approval_and_disables_on_approve(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("rogue_agent", "viewer", ["get_ip_reputation"])

    proposal = mcp_gateway.authorize_and_execute("revoke_agent_credentials", "agent_security", "rogue_agent",
                                                  {"agent_id": "rogue_agent"})
    assert proposal.status == "pending_approval"
    assert agent_registry.get_agent("rogue_agent")["disabled"] is False  # not yet

    result = mcp_gateway.execute_approved_call(proposal.call_id, decided_by="admin")
    assert result["disabled"] is True
    assert agent_registry.get_agent("rogue_agent")["disabled"] is True  # re-read, verified


def test_revoke_agent_credentials_scoped_to_agent_security_only(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    result = mcp_gateway.authorize_and_execute("revoke_agent_credentials", "authentication", "someone",
                                                {"agent_id": "someone"})
    assert result.status == "denied_out_of_scope"


def test_remove_agent_tool_access_requires_approval_and_removes_on_approve(monkeypatch, temp_sqlite_path):
    _patch_common(monkeypatch, temp_sqlite_path)
    agent_registry.register_agent("borderline_agent", "admin", ["get_ip_reputation", "block_ip"])

    arguments = {"agent_id": "borderline_agent", "tool_name": "block_ip"}
    proposal = mcp_gateway.authorize_and_execute("remove_agent_tool_access", "agent_security",
                                                  "borderline_agent", arguments)
    assert proposal.status == "pending_approval"
    assert "block_ip" in agent_registry.get_agent("borderline_agent")["allowed_tools"]  # not yet

    result = mcp_gateway.execute_approved_call(proposal.call_id, decided_by="admin")
    assert result["removed_tool"] == "block_ip"
    assert "block_ip" not in agent_registry.get_agent("borderline_agent")["allowed_tools"]
    assert "get_ip_reputation" in agent_registry.get_agent("borderline_agent")["allowed_tools"]
