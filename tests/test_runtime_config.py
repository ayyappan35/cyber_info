from common import config
from security_gateway import runtime_config


def _reset(monkeypatch, **overrides):
    settings = config.Settings(**overrides)
    monkeypatch.setattr(runtime_config, "get_settings", lambda: settings)
    runtime_config.reset_to_configured_default()
    return settings


def test_defaults_to_configured_provider(monkeypatch):
    _reset(monkeypatch, llm_provider="ollama", ollama_model="llama3.2:3b")
    assert runtime_config.get_active_provider() == "ollama"
    assert runtime_config.get_active_model() == "llama3.2:3b"
    assert runtime_config.status()["is_override"] is False


def test_switch_to_anthropic_with_key_configured(monkeypatch):
    _reset(monkeypatch, llm_provider="ollama", anthropic_api_key="sk-test",
           anthropic_model="claude-sonnet-5")
    runtime_config.set_active_provider("anthropic")
    assert runtime_config.get_active_provider() == "anthropic"
    assert runtime_config.get_active_model() == "claude-sonnet-5"
    assert runtime_config.status()["is_override"] is True


def test_switch_to_anthropic_without_key_raises(monkeypatch):
    _reset(monkeypatch, llm_provider="ollama", anthropic_api_key=None)
    try:
        runtime_config.set_active_provider("anthropic")
        assert False, "expected ValueError"
    except ValueError as e:
        assert "ANTHROPIC_API_KEY" in str(e)
    assert runtime_config.get_active_provider() == "ollama"  # unchanged on failure


def test_switch_to_unsupported_provider_raises(monkeypatch):
    _reset(monkeypatch, llm_provider="ollama")
    try:
        runtime_config.set_active_provider("openai")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_reset_reverts_to_configured_default(monkeypatch):
    _reset(monkeypatch, llm_provider="ollama", anthropic_api_key="sk-test")
    runtime_config.set_active_provider("anthropic")
    assert runtime_config.get_active_provider() == "anthropic"

    runtime_config.reset_to_configured_default()
    assert runtime_config.get_active_provider() == "ollama"
    assert runtime_config.status()["is_override"] is False


def test_status_reports_anthropic_availability(monkeypatch):
    _reset(monkeypatch, llm_provider="ollama", anthropic_api_key=None)
    assert runtime_config.status()["anthropic_available"] is False

    _reset(monkeypatch, llm_provider="ollama", anthropic_api_key="sk-test")
    assert runtime_config.status()["anthropic_available"] is True
