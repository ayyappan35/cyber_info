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
import re
from typing import Any

from common.config import get_settings

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

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    handler.addFilter(RedactSecretsFilter())
    handler._cyberdefense_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
