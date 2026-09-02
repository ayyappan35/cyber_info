"""Tests for backend/pipelines/chat_agent.py - the agentic multi-turn
chat loop. Tool functions and the context accumulator are tested for
real; the LLM loop mechanics are tested with the provider call mocked
out, matching this project's established split (pytest for logic, live
runs for the actual model call)."""
from common import config
import pytest
from common import security_db
import webapp_db as db
from pipelines import chat_agent
from security_gateway import mcp_gateway
from security_gateway.mcp_tools import redis_tool


def _set_provider(monkeypatch, **overrides):
    settings = config.Settings(**overrides)
    monkeypatch.setattr(chat_agent.runtime_config, "get_settings", lambda: settings)
    chat_agent.runtime_config.reset_to_configured_default()


def _patch_gateway(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()
    db.init_db()
    monkeypatch.setattr(redis_tool, "REDIS_URL", "")
    monkeypatch.setattr(redis_tool, "_client", None)
    import collections
    monkeypatch.setattr(mcp_gateway, "_tool_calls", collections.defaultdict(collections.deque))


def test_accumulator_collects_chunks_and_sources():
    acc = chat_agent._Accumulator()
    acc.add_search_result({"results": [{"content": "chunk one", "source": "a.md"},
                                        {"content": "chunk two", "source": "b.md"}]})
    acc.add_search_result({"results": [{"content": "chunk three", "source": "a.md"}]})
    assert acc.sources == {"a.md", "b.md"}
    assert "chunk one" in acc.context
    assert "chunk three" in acc.context
    assert acc.context.count("<document") == 3


def test_accumulator_empty_results_no_crash():
    acc = chat_agent._Accumulator()
    acc.add_search_result({"results": []})
    assert acc.sources == set()
    assert acc.context == ""


def test_accumulator_records_external_query_and_merges_content():
    acc = chat_agent._Accumulator()
    acc.add_external_result("what is python", {
        "abstract": "Python is a programming language.",
        "related_topics": [{"text": "Python (genus)", "url": "https://x"}],
    })
    assert acc.external_queries == ["what is python"]
    assert "Python is a programming language." in acc.context
    assert "Python (genus)" in acc.context
    assert any(s.startswith("external:duckduckgo:") for s in acc.sources)


def test_accumulator_external_error_result_not_merged_but_query_recorded():
    acc = chat_agent._Accumulator()
    acc.add_external_result("http://192.168.1.1", {"error": "blocked: query appears to target..."})
    assert acc.external_queries == ["http://192.168.1.1"]
    assert acc.context == ""
    assert acc.sources == set()


def test_tool_search_knowledge_base_uses_real_search(monkeypatch):
    def fake_search_knowledge(query, top_k=4, category_filter=None):
        assert query == "brute force"
        return [{"content": "x" * 900, "source": "runbook.md"}]
    monkeypatch.setattr(chat_agent, "search_knowledge", fake_search_knowledge)

    result = chat_agent._tool_search_knowledge_base("brute force")
    assert result["results"][0]["source"] == "runbook.md"
    assert len(result["results"][0]["content"]) == 800  # truncated


def test_tool_get_skill_methodology_returns_real_skill_content():
    result = chat_agent._tool_get_skill_methodology("authentication", "brute-force")
    assert "content" in result
    assert "brute" in result["content"].lower()


def test_tool_get_skill_methodology_invalid_skill():
    result = chat_agent._tool_get_skill_methodology("authentication", "not-a-real-skill")
    assert "error" in result


def test_search_external_web_tool_routes_through_mcp_gateway(monkeypatch, temp_sqlite_path):
    _patch_gateway(monkeypatch, temp_sqlite_path)
    called = {}

    def fake_authorize_and_execute(tool_name, request_category, identity, evidence, decision_id=None):
        called["args"] = (tool_name, request_category, identity, evidence)
        return mcp_gateway.ToolResult(tool_name=tool_name, status="authorized_executed",
                                       result={"abstract": "ok"})
    monkeypatch.setattr(chat_agent.mcp_gateway, "authorize_and_execute", fake_authorize_and_execute)

    tool = chat_agent._make_search_external_web("alice")
    result = tool("what is python")
    assert result == {"abstract": "ok"}
    assert called["args"] == ("search_external_web", "rag_security", "alice", {"query": "what is python"})


def test_search_external_web_tool_surfaces_denial_as_error(monkeypatch):
    monkeypatch.setattr(chat_agent.mcp_gateway, "authorize_and_execute",
                         lambda *a, **k: mcp_gateway.ToolResult(tool_name="search_external_web",
                                                                  status="denied_rate_limited",
                                                                  reason="rate limit exceeded"))
    tool = chat_agent._make_search_external_web("alice")
    result = tool("anything")
    assert result == {"error": "rate limit exceeded"}


def test_get_user_details_strips_password_hash(monkeypatch, temp_sqlite_path):
    _patch_gateway(monkeypatch, temp_sqlite_path)
    db.create_user("bob", "supersecrethash", email="bob@example.com", role="user")
    funcs = chat_agent._make_admin_tools("adminuser")
    result = funcs["get_user_details"]("bob")
    assert result["found"] is True
    assert result["email"] == "bob@example.com"
    assert "password_hash" not in result
    assert "supersecrethash" not in str(result)


def test_get_user_details_not_found(monkeypatch, temp_sqlite_path):
    _patch_gateway(monkeypatch, temp_sqlite_path)
    funcs = chat_agent._make_admin_tools("adminuser")
    result = funcs["get_user_details"]("nobody")
    assert result == {"found": False}


def test_list_users_password_hash_free(monkeypatch, temp_sqlite_path):
    _patch_gateway(monkeypatch, temp_sqlite_path)
    db.create_user("carol", "hash", email="carol@example.com", role="user")
    funcs = chat_agent._make_admin_tools("adminuser")
    result = funcs["list_users"]()
    assert any(u["username"] == "carol" for u in result["users"])
    assert "password_hash" not in str(result)


def test_tools_for_role_admin_gets_admin_tools_and_search_external_web():
    specs, funcs = chat_agent._tools_for_role("admin", "adminuser")
    names = {s["name"] for s in specs}
    assert {"search_knowledge_base", "get_skill_methodology", "search_external_web",
            "get_user_details", "list_users"} <= names
    assert set(funcs.keys()) == names


def test_tools_for_role_non_admin_never_sees_admin_tools():
    specs, funcs = chat_agent._tools_for_role("user", "regularuser")
    names = {s["name"] for s in specs}
    assert "get_user_details" not in names
    assert "list_users" not in names
    assert "get_user_details" not in funcs
    assert "search_external_web" in names  # not admin-only - available to every caller


async def test_run_chat_agent_dispatches_to_ollama(monkeypatch):
    _set_provider(monkeypatch, llm_provider="ollama", ollama_model="llama3.2:3b")

    called = {}
    async def fake_ollama(question, model, max_turns, log, on_event, tool_specs, tool_funcs):
        called["model"] = model
        return {"answer": "ok", "sources": [], "transcript": [], "context": "", "external_queries": []}
    monkeypatch.setattr(chat_agent, "_run_ollama", fake_ollama)

    result = await chat_agent.run_chat_agent("hi")
    assert result["answer"] == "ok"
    assert called["model"] == "llama3.2:3b"


async def test_run_chat_agent_dispatches_to_anthropic(monkeypatch):
    _set_provider(monkeypatch, llm_provider="anthropic", anthropic_model="claude-sonnet-5",
                   anthropic_api_key="sk-test")

    called = {}
    async def fake_anthropic(question, model, max_turns, log, on_event, tool_specs, tool_funcs):
        called["model"] = model
        return {"answer": "ok", "sources": [], "transcript": [], "context": "", "external_queries": []}
    monkeypatch.setattr(chat_agent, "_run_anthropic", fake_anthropic)

    result = await chat_agent.run_chat_agent("hi")
    assert result["answer"] == "ok"
    assert called["model"] == "claude-sonnet-5"


async def test_run_chat_agent_unknown_provider_raises(monkeypatch):
    _set_provider(monkeypatch, llm_provider="ollama")
    monkeypatch.setattr(chat_agent.runtime_config, "get_active_provider", lambda: "openai")

    with pytest.raises(NotImplementedError):
        await chat_agent.run_chat_agent("hi")


# --- turn-1 no-tool-call acceptance (2026-09-02) --------------------------
# Real behavior change: the model's own FIRST-turn judgment (per
# SYSTEM_PROMPT's greeting instruction) is now trusted directly rather
# than forcing a "ground your answer with a tool call" retry - no code-
# level classification (e.g. a regex "is this a greeting" check) of the
# question happens anywhere in this module. These tests exercise the
# real provider-loop mechanics (not the dispatch-level mocking above) to
# prove exactly one model call happens for a plain greeting-shaped
# no-tool answer, and that a real multi-turn tool-using flow is
# unaffected.

class _FakeOllamaResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeOllamaClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.call_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json):
        self.call_count += 1
        return _FakeOllamaResponse(self._responses.pop(0))


async def test_run_ollama_accepts_turn_one_no_tool_answer_without_nudging(monkeypatch):
    import httpx
    fake_client = _FakeOllamaClient([
        {"message": {"role": "assistant", "content": "Hello! How can I help you today?", "tool_calls": None}},
    ])
    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=None: fake_client)

    result = await chat_agent._run_ollama("hi", "llama3.2:3b", 4, print, None, [], {})
    assert result["answer"] == "Hello! How can I help you today?"
    assert fake_client.call_count == 1  # accepted immediately - no forced grounding retry


async def test_run_ollama_multiturn_tool_flow_still_works(monkeypatch):
    import httpx
    fake_client = _FakeOllamaClient([
        {"message": {"role": "assistant", "content": "", "tool_calls": [
            {"function": {"name": "search_knowledge_base", "arguments": {"query": "brute force"}}},
        ]}},
        {"message": {"role": "assistant", "content": "Brute force is repeated login attempts.",
                      "tool_calls": None}},
    ])
    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=None: fake_client)
    tool_funcs = {"search_knowledge_base": lambda query, category_filter=None:
                  {"results": [{"content": "Brute force runbook text", "source": "runbook.md"}]}}

    result = await chat_agent._run_ollama("what is brute force?", "llama3.2:3b", 4, print, None,
                                           [{"name": "search_knowledge_base", "description": "d",
                                             "parameters": {"type": "object", "properties": {}}}],
                                           tool_funcs)
    assert result["answer"] == "Brute force is repeated login attempts."
    assert result["sources"] == ["runbook.md"]
    assert fake_client.call_count == 2


class _FakeTextBlock:
    type = "text"

    def __init__(self, text):
        self.text = text


class _FakeAnthropicResponse:
    def __init__(self, content):
        self.content = content


class _FakeAnthropicMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.call_count = 0

    async def create(self, **kwargs):
        self.call_count += 1
        return self._responses.pop(0)


class _FakeAnthropicClient:
    def __init__(self, responses):
        self.messages = _FakeAnthropicMessages(responses)


async def test_run_anthropic_accepts_turn_one_no_tool_answer_without_nudging(monkeypatch):
    fake_client = _FakeAnthropicClient([_FakeAnthropicResponse([_FakeTextBlock("Hello! How can I help you today?")])])
    monkeypatch.setattr(chat_agent, "get_settings",
                         lambda: config.Settings(anthropic_api_key="sk-test"))
    import anthropic
    monkeypatch.setattr(anthropic, "AsyncAnthropic", lambda api_key=None: fake_client)

    result = await chat_agent._run_anthropic("hi", "claude-sonnet-5", 4, print, None, [], {})
    assert result["answer"] == "Hello! How can I help you today?"
    assert fake_client.messages.call_count == 1  # accepted immediately - no forced grounding retry
