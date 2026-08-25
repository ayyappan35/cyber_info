"""Tests for the LLM_PROVIDER dispatch in security_gateway/llm_discussion.py
- both provider implementations mocked out (no real Ollama/Claude calls),
matching this project's established split (pytest for logic, live runs
for the actual model call).

discuss() resolves provider/model via security_gateway/runtime_config.py
(so a runtime provider switch takes effect without a restart - see that
module), not directly from config.get_settings() - tests that exercise
discuss()'s dispatch patch `runtime_config.get_settings` and reset any
override first, rather than patching llm_discussion.get_settings (which
only affects _discuss_ollama/_discuss_anthropic's own internal calls,
e.g. the base URL / API key lookups inside them).
"""
from common import config
from security_gateway import llm_discussion, runtime_config
from security_gateway.decision import SecurityDecision


def _fake_skill():
    return {"skill_id": "brute-force", "category": "authentication", "content": "test skill content"}


def _set_provider_settings(monkeypatch, **overrides):
    settings = config.Settings(**overrides)
    monkeypatch.setattr(runtime_config, "get_settings", lambda: settings)
    runtime_config.reset_to_configured_default()
    return settings


def test_build_prompt_includes_skill_content_and_tools():
    system, user = llm_discussion._build_prompt(
        "authentication", [_fake_skill()], {"username": "alice"}, [], ["get_login_attempts"],
    )
    assert "test skill content" in user
    assert "get_login_attempts" in system
    assert "brute-force" in user


def test_build_prompt_no_tools_available():
    system, user = llm_discussion._build_prompt("authentication", [_fake_skill()], {}, [], [])
    assert "none available for this category" in system


async def test_discuss_dispatches_to_ollama(monkeypatch):
    _set_provider_settings(monkeypatch, llm_provider="ollama", ollama_model="llama3.2:3b")

    called = {}
    async def fake_ollama(system, user, model, max_retries, log):
        called["model"] = model
        return SecurityDecision(action="ALLOW", confidence=0.9, reasoning="fine")
    monkeypatch.setattr(llm_discussion, "_discuss_ollama", fake_ollama)

    result = await llm_discussion.discuss("authentication", [_fake_skill()], {}, [])
    assert result.action == "ALLOW"
    assert called["model"] == "llama3.2:3b"


async def test_discuss_dispatches_to_anthropic(monkeypatch):
    _set_provider_settings(monkeypatch, llm_provider="anthropic", anthropic_model="claude-sonnet-5",
                            anthropic_api_key="sk-test")

    called = {}
    async def fake_anthropic(system, user, model, max_retries, log):
        called["model"] = model
        return SecurityDecision(action="BLOCK", confidence=0.95, reasoning="clear pattern")
    monkeypatch.setattr(llm_discussion, "_discuss_anthropic", fake_anthropic)

    result = await llm_discussion.discuss("authentication", [_fake_skill()], {}, [])
    assert result.action == "BLOCK"
    assert called["model"] == "claude-sonnet-5"


async def test_discuss_unknown_provider_raises(monkeypatch):
    # openai is declared in config.py but not implemented in llm_discussion.py.
    # runtime_config.set_active_provider() itself rejects it (see
    # test_runtime_config.py), so this exercises discuss()'s own defensive
    # check by going through the configured-default path directly.
    _set_provider_settings(monkeypatch, llm_provider="ollama")
    monkeypatch.setattr(runtime_config, "get_active_provider", lambda: "openai")

    try:
        await llm_discussion.discuss("authentication", [_fake_skill()], {}, [])
        assert False, "expected NotImplementedError"
    except NotImplementedError as e:
        assert "openai" in str(e)


async def test_discuss_explicit_model_overrides_settings(monkeypatch):
    _set_provider_settings(monkeypatch, llm_provider="ollama", ollama_model="llama3.2:3b")

    called = {}
    async def fake_ollama(system, user, model, max_retries, log):
        called["model"] = model
        return SecurityDecision(action="ALLOW", confidence=0.9, reasoning="fine")
    monkeypatch.setattr(llm_discussion, "_discuss_ollama", fake_ollama)

    await llm_discussion.discuss("authentication", [_fake_skill()], {}, [], model="llama3.2:70b")
    assert called["model"] == "llama3.2:70b"


async def test_discuss_anthropic_missing_api_key_fails_closed(monkeypatch):
    settings = config.Settings(llm_provider="anthropic", anthropic_model="claude-sonnet-5",
                                anthropic_api_key=None)
    monkeypatch.setattr(llm_discussion, "get_settings", lambda: settings)

    try:
        await llm_discussion._discuss_anthropic("sys", "user", "claude-sonnet-5", 0, print)
        assert False, "expected DiscussionFailed"
    except llm_discussion.DiscussionFailed as e:
        assert "ANTHROPIC_API_KEY" in str(e)
