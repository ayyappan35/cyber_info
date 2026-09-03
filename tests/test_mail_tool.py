"""security_gateway/mcp_tools/mail_tool.py - OTP delivery for the
account-takeover MFA hold. No SMTP_HOST is set in this test environment,
so every test here exercises the local-outbox fallback path (real
persisted record, not a fake/no-op send) - see mail_tool.py's docstring
and redis_tool.py for the same real-backend-or-honest-local-fallback
pattern this follows. backend/ is on sys.path via tests/conftest.py."""
import webapp_db as db
from security_gateway.mcp_tools import mail_tool


def test_backend_is_local_outbox_when_smtp_not_configured(monkeypatch):
    monkeypatch.setattr(mail_tool, "SMTP_HOST", "")
    assert mail_tool.backend() == "local-outbox"


def test_backend_is_smtp_when_smtp_host_configured(monkeypatch):
    monkeypatch.setattr(mail_tool, "SMTP_HOST", "smtp.example.com")
    assert mail_tool.backend() == "smtp"


def test_send_otp_email_falls_back_to_local_outbox(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    db.init_db()
    monkeypatch.setattr(mail_tool, "SMTP_HOST", "")

    result = mail_tool.send_otp_email("user@example.com", "someuser", "123456")

    assert result == {"delivered_via": "local-outbox", "to_email": "user@example.com"}
    mail = db.list_outbox(to_email="user@example.com")
    assert len(mail) == 1
    assert "123456" in mail[0]["body"]
    assert "someuser" in mail[0]["body"]
