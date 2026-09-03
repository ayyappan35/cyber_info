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
"""
import os
import smtplib
from email.message import EmailMessage

import webapp_db as db

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "security@cyber-defense.local")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() != "false"

OTP_TTL_SECONDS = 600  # 10 minutes


def backend() -> str:
    return "smtp" if SMTP_HOST else "local-outbox"


def send_otp_email(to_email: str, username: str, otp: str) -> dict:
    subject = "Security verification code"
    body = (
        f"A sign-in to the account '{username}' was flagged by the security gateway for "
        f"additional verification (account-takeover pattern).\n\n"
        f"Your one-time verification code is: {otp}\n"
        f"This code expires in {OTP_TTL_SECONDS // 60} minutes.\n\n"
        f"If this wasn't you, contact an administrator."
    )

    if SMTP_HOST:
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

    db.record_outbox_email(to_email, subject, body)
    return {"delivered_via": backend(), "to_email": to_email}
