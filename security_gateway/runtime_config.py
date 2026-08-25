"""Runtime LLM provider/model override - lets an admin switch between
Ollama and Claude from the UI without restarting the backend, on top of
config.py's .env-driven default (which still applies until someone
switches). In-process only (a plain module-level dict, no persistence) -
a restart reverts to the .env default, which is the right behavior for a
single-process dev deployment: there is no multi-worker state to keep in
sync (same documented constraint security_gateway/mcp_tools/redis_tool.py
already carries for its in-process rate tracking).
"""
from common.config import get_settings

SUPPORTED_PROVIDERS = ("ollama", "anthropic")  # openai is declared in config.py but not implemented

_active_provider = None  # None = use settings.llm_provider (the .env default)


def get_active_provider() -> str:
    return _active_provider or get_settings().llm_provider


def get_active_model() -> str:
    settings = get_settings()
    provider = get_active_provider()
    return {"ollama": settings.ollama_model, "anthropic": settings.anthropic_model}.get(
        provider, settings.active_model())


def set_active_provider(provider: str) -> None:
    global _active_provider
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"provider must be one of {SUPPORTED_PROVIDERS} (openai is not implemented)")
    if provider == "anthropic" and not get_settings().anthropic_api_key:
        raise ValueError("ANTHROPIC_API_KEY is not set in .env - cannot switch to anthropic")
    _active_provider = provider


def reset_to_configured_default() -> None:
    global _active_provider
    _active_provider = None


def status() -> dict:
    settings = get_settings()
    return {
        "provider": get_active_provider(),
        "model": get_active_model(),
        "configured_default_provider": settings.llm_provider,
        "is_override": _active_provider is not None,
        "anthropic_available": bool(settings.anthropic_api_key),
    }
