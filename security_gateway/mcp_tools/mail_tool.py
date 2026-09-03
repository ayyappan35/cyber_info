"""Mail MCP tool: delivers the OTP challenge require_mfa
(security_gateway/mcp_gateway.py) puts on an account after an
account-takeover verdict (skills/authentication/account-takeover).

Real SMTP is used when SMTP_HOST is set - a genuine smtplib send, not a
stub. If it isn't configured (the common case for local development,
where no mail server is reachable), this falls back to a real,
persisted local outbox (webapp_db.mail_outbox) instead of a fake/no-op
send - the exact same "real local substitute, not a fake implementation"
pattern redis_tool.py uses for its sqlite fallback. Which path is active
is reported by `backend()` so callers/docs stay honest about it, and the
outbox is always written to regardless of backend, so an admin/tester
can always retrieve the code (GET /api/admin/mail-outbox) even when SMTP
is configured.

Sourced from common/config.py's Settings (real .env-file loading via
pydantic-settings), not a bare os.environ.get() - per that module's own
docstring, new code should read settings from there so a value set in
.env actually takes effect, which a plain os.environ.get() here would
silently NOT do (pydantic-settings loads .env into its own Settings
instance, it does not populate the process environment)."""
import smtplib
from email.message import EmailMessage

import webapp_db as db
from common.config import get_settings

_settings = get_settings()
SMTP_HOST = _settings.smtp_host
SMTP_PORT = _settings.smtp_port
SMTP_USER = _settings.smtp_user
SMTP_PASSWORD = _settings.smtp_password
SMTP_FROM = _settings.smtp_from
SMTP_USE_TLS = _settings.smtp_use_tls

OTP_TTL_SECONDS = 600  # 10 minutes


def backend() -> str:
    return "smtp" if SMTP_HOST else "local-outbox"


def send_otp_email(to_email: str, username: str, otp: str) -> dict:
    """A real SMTP failure (bad recipient, auth failure, network timeout -
    all real possibilities, not hypothetical) must never crash this call:
    by the time this runs, require_mfa has already written the hold and
    OTP hash to the account (security_gateway/mcp_gateway.py::
    _exec_require_mfa), and an uncaught exception here would propagate
    all the way up through authorize_and_execute() into a 500 on the
    user's login request - locking them out with no code ever delivered
    anywhere. The local outbox write is the honest fallback of record
    either way; `delivered_via` reports what actually happened this call,
    not just what's configured (see `backend()` for that)."""
    subject = "Security verification code"
    body = (
        f"A sign-in to the account '{username}' was flagged by the security gateway for "
        f"additional verification (account-takeover pattern).\n\n"
        f"Your one-time verification code is: {otp}\n"
        f"This code expires in {OTP_TTL_SECONDS // 60} minutes.\n\n"
        f"If this wasn't you, contact an administrator."
    )

    delivered_via = "local-outbox"
    if SMTP_HOST:
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = SMTP_FROM
            msg["To"] = to_email
            msg.set_content(body)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                if SMTP_USE_TLS:
                    server.starttls()
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
            delivered_via = "smtp"
        except Exception:
            delivered_via = "smtp_failed"

    db.record_outbox_email(to_email, subject, body)
    return {"delivered_via": delivered_via, "to_email": to_email}
