"""Central, env-driven configuration for the whole project.

This is new infrastructure, not a rewire: existing modules (agents/ollama_agent.py's
OLLAMA_URL, db.py/security_db.py/backend/webapp_db.py's DB_PATH, backend/auth.py's
JWT_SECRET file-fallback) keep working exactly as they do today. New code - the
LLM/RAG/Agentic defense agents added on top of this platform (Input Defence, RAG
Defence, Memory Defence, etc.) - should read settings from here instead of adding
more scattered os.environ.get() calls, and the existing hardcoded defaults get
migrated to read from here opportunistically as each module is next touched, per
CLAUDE.md's "do not unnecessarily rewrite working components."

Loads a `.env` file at the project root if present (see .env.example), then
environment variables, then falls back to the defaults below. Never hardcode a
real API key here - only Ollama's *local, unauthenticated* endpoint has a
default value, since it points at localhost with nothing to leak.
"""
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- LLM provider (CLAUDE.md section 2: configurable, no hardcoded keys) ---
    llm_provider: Literal["ollama", "anthropic", "openai"] = Field(default="ollama")

    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3.2:3b")

    anthropic_api_key: Optional[str] = Field(default=None)
    anthropic_model: str = Field(default="claude-sonnet-5")

    openai_api_key: Optional[str] = Field(default=None)
    openai_model: str = Field(default="gpt-4o-mini")

    # --- Storage paths ---
    db_path: str = Field(default=str(PROJECT_ROOT / "cyberdefense.db"))
    chroma_dir: str = Field(default=str(PROJECT_ROOT / "kb_chroma_db"))
    knowledge_dir: str = Field(default=str(PROJECT_ROOT / "knowledge"))

    # --- Auth ---
    jwt_secret: Optional[str] = Field(default=None)

    # --- CORS (backend/main.py) ---
    # Comma-separated origins. Local dev + the deployed frontend
    # (https://cyber-info-2.onrender.com) by default - add more via
    # CORS_ALLOWED_ORIGINS in .env rather than editing this file again.
    cors_allowed_origins: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173,https://cyber-info-2.onrender.com"
    )

    def cors_origins_list(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.cors_allowed_origins.split(",") if o.strip()]

    # --- Mail (account-takeover OTP delivery, security_gateway/mcp_tools/mail_tool.py) ---
    smtp_host: str = Field(default="")
    smtp_port: int = Field(default=587)
    smtp_user: str = Field(default="")
    smtp_password: str = Field(default="")
    smtp_from: str = Field(default="security@cyber-defense.local")
    smtp_use_tls: bool = Field(default=True)

    # --- Observability (CLAUDE.md section 15) ---
    log_level: str = Field(default="INFO")
    tracing_backend: Literal["none", "mlflow", "langsmith"] = Field(default="none")
    mlflow_tracking_uri: Optional[str] = Field(default=None)
    mlflow_experiment_name: str = Field(default="cyber-defense-assistant")
    langsmith_api_key: Optional[str] = Field(default=None)
    langsmith_project: str = Field(default="cyber-defense-assistant")

    def active_model(self) -> str:
        """The model name for whichever provider is currently selected."""
        return {
            "ollama": self.ollama_model,
            "anthropic": self.anthropic_model,
            "openai": self.openai_model,
        }[self.llm_provider]


@lru_cache
def get_settings() -> Settings:
    return Settings()
