"""webapp_db.py's account-lock lifecycle - agentic_system branch.
LOCKOUT_THRESHOLD's fixed-count auto-lock is REMOVED on this branch;
record_failed_login() only tracks a counter now, and lock_account() (the
only way an account gets locked) is called by backend/routers/
auth_router.py exactly when security_gateway/gateway.py's Security LLM
verdict is BLOCK - see docs/AGENTIC_SYSTEM_EXPERIMENT.md. backend/ is on
sys.path via tests/conftest.py."""
import webapp_db as db


def test_record_failed_login_never_auto_locks(monkeypatch, temp_sqlite_path):
    # Real behavior change from main: no fixed threshold locks the
    # account anymore, no matter how many failed attempts accumulate -
    # only lock_account() (driven by the agentic gateway verdict) can.
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    db.init_db()
    db.create_user("alice", "hash", email="alice@example.com")

    for i in range(1, 11):
        result = db.record_failed_login("alice")
        assert result["locked"] is False
        assert result["failed_attempts"] == i
    assert db.get_user("alice")["locked"] == 0


def test_lock_account_sets_locked_directly(monkeypatch, temp_sqlite_path):
    # This is the ONLY path to locked=1 on this branch - called from
    # auth_router.py when the Security LLM's own verdict is BLOCK, not
    # from any failed-attempt counter.
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    db.init_db()
    db.create_user("alice", "hash", email="alice@example.com")
    assert db.get_user("alice")["locked"] == 0

    locked = db.lock_account("alice")
    assert locked is True
    assert db.get_user("alice")["locked"] == 1


def test_lock_account_unknown_username_returns_false(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    db.init_db()
    assert db.lock_account("nobody") is False


def test_unlock_account_clears_lock_and_failed_attempts(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    db.init_db()
    db.create_user("bob", "hash", email="bob@example.com")
    db.record_failed_login("bob")
    db.record_failed_login("bob")
    db.lock_account("bob")
    assert db.get_user("bob")["locked"] == 1

    unlocked = db.unlock_account("bob")
    assert unlocked is True
    user = db.get_user("bob")
    assert user["locked"] == 0
    assert user["failed_attempts"] == 0


def test_unlocked_account_survives_one_more_failed_login(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    db.init_db()
    db.create_user("carol", "hash", email="carol@example.com")
    db.lock_account("carol")
    assert db.get_user("carol")["locked"] == 1

    db.unlock_account("carol")
    result = db.record_failed_login("carol")  # one more wrong password after unlock
    assert result["locked"] is False
    assert result["failed_attempts"] == 1


def test_unlock_account_unknown_username_returns_false(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    db.init_db()
    assert db.unlock_account("nobody") is False


def test_list_users_includes_mfa_hold(monkeypatch, temp_sqlite_path):
    # Real gap (2026-09-02): list_users() didn't select mfa_hold at all,
    # so the Admin Dashboard's Users tab had no way to show or clear a
    # require_mfa hold (security_gateway/mcp_gateway.py) even though the
    # column and set_mfa_hold() already existed.
    monkeypatch.setattr(db, "DB_PATH", temp_sqlite_path)
    db.init_db()
    db.create_user("gwen", "hash", email="gwen@example.com")
    db.set_mfa_hold("gwen", True)

    users = db.list_users()
    gwen = next(u for u in users if u["username"] == "gwen")
    assert gwen["mfa_hold"] == 1
