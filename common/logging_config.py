"""Structured logging setup (CLAUDE.md section 15: observability, and section
2's "never log secrets/credentials/API keys/tokens").

This is additive: orchestrator.py's own log(msg) print-callback pattern and
each agent's `log` parameter keep working unchanged - that pattern is how the
live red/blue/governance narration streams to the console and is intentionally
simple. setup_logging() instead configures Python's stdlib `logging` module for
everything else (FastAPI/uvicorn, and new agents as they're added), so both can
coexist: orchestrator's demo narration stays readable, and everything else gets
leveled, timestamped, filterable log records.
"""
import logging
import os
import re
from logging.handlers import RotatingFileHandler

from common.config import get_settings

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(_PROJECT_ROOT, "logs", "security_gateway.log")

# Best-effort redaction for anything accidentally logged that looks like a
# secret. Not a substitute for not logging secrets in the first place - just
# a last-line-of-defense filter.
_SECRET_PATTERNS = [
    re.compile(r"(api[_-]?key\s*[=:]\s*)([^\s'\"]+)", re.IGNORECASE),
    re.compile(r"(authorization:\s*bearer\s+)([^\s'\"]+)", re.IGNORECASE),
    re.compile(r"(password\s*[=:]\s*)([^\s'\"]+)", re.IGNORECASE),
]


class RedactSecretsFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        redacted = msg
        for pattern in _SECRET_PATTERNS:
            redacted = pattern.sub(r"\1***REDACTED***", redacted)
        if redacted != msg:
            record.msg = redacted
            record.args = ()
        return True


def setup_logging(level: str | None = None) -> None:
    """Idempotent: safe to call multiple times (e.g. once from backend/main.py's
    lifespan and again from a test fixture) without duplicating handlers."""
    settings = get_settings()
    resolved_level = getattr(logging, (level or settings.log_level).upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(resolved_level)

    if any(isinstance(h, logging.StreamHandler) and getattr(h, "_cyberdefense_handler", False)
           for h in root.handlers):
        return

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.addFilter(RedactSecretsFilter())
    handler._cyberdefense_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)

    # Persists everything the console handler above prints - including
    # gateway.py::analyze()'s step-by-step pipeline narration (passed
    # through as `log=app.state.log` -> this same `logger.info`) - to a
    # real file on disk. Without this, "what evidence did my login send to
    # the Security LLM" only ever existed in the console the server
    # happened to be running in, gone the moment it scrolled past or the
    # process restarted - not usable for a demo or after-the-fact review.
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.addFilter(RedactSecretsFilter())
    file_handler._cyberdefense_handler = True  # type: ignore[attr-defined]
    root.addHandler(file_handler)

    # Real, observed problem (2026-09-06): threat_knowledge.py's embedding/
    # reranker model calls (sentence_transformers -> huggingface_hub -> httpx)
    # log dozens of INFO-level HTTP request lines per gateway.analyze() call -
    # at root INFO level these drown out the actual STEP 1/5..5/5 security
    # narration in logs/security_gateway.log, defeating its purpose as a
    # readable step-by-step trail. These are noisy, not useful, at INFO here -
    # WARNING still surfaces anything actually wrong with them.
    for _noisy_logger in ("httpx", "httpcore", "urllib3", "sentence_transformers", "huggingface_hub"):
        logging.getLogger(_noisy_logger).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
