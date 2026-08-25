from common import security_db


def test_gateway_decision_roundtrip(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()

    decision_id = security_db.log_gateway_decision(
        category="authentication", identity="alice", action="BLOCK", raw_action="BLOCK",
        confidence=0.9, threat_indicators=["many failures"], reasoning="test", enforced=True,
        sandbox_id=None,
    )
    assert decision_id > 0
    rows = security_db.list_gateway_decisions(limit=10)
    assert len(rows) == 1
    assert rows[0]["category"] == "authentication"
    assert rows[0]["threat_indicators"] == ["many failures"]
    assert rows[0]["enforced"] == 1


def test_gateway_decisions_filtered_by_category(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()
    security_db.log_gateway_decision(category="authentication", identity="a", action="ALLOW",
                                      raw_action="ALLOW", confidence=0.9, threat_indicators=[],
                                      reasoning="", enforced=True)
    security_db.log_gateway_decision(category="file_security", identity="b", action="ALLOW",
                                      raw_action="ALLOW", confidence=0.9, threat_indicators=[],
                                      reasoning="", enforced=True)
    rows = security_db.list_gateway_decisions(category="file_security")
    assert len(rows) == 1
    assert rows[0]["category"] == "file_security"


def test_block_identity_and_expiry(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()
    assert security_db.is_identity_blocked("bob", "authentication") is False
    security_db.block_identity("bob", "authentication", "brute force", ttl_seconds=900)
    assert security_db.is_identity_blocked("bob", "authentication") is True
    assert security_db.is_identity_blocked("bob", "file_security") is False  # scoped per category
    blocked = security_db.list_blocked_identities()
    assert any(b["identity"] == "bob" for b in blocked)


def test_block_identity_expired_not_blocked(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()
    security_db.block_identity("carol", "authentication", "test", ttl_seconds=-10)  # already expired
    assert security_db.is_identity_blocked("carol", "authentication") is False


def test_sandbox_roundtrip(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()
    security_db.sandbox_put("sbx_1", category="rag_security", identity="dave", kind="text",
                             content="flagged question+context", metadata={"reasoning": "test"})

    item = security_db.sandbox_get("sbx_1")
    assert item["content"] == "flagged question+context"
    assert item["metadata"]["reasoning"] == "test"
    assert item["released"] == 0

    unreleased = security_db.sandbox_list(released=False)
    assert len(unreleased) == 1

    security_db.sandbox_release("sbx_1")
    assert security_db.sandbox_get("sbx_1")["released"] == 1
    assert security_db.sandbox_list(released=False) == []
    assert len(security_db.sandbox_list(released=True)) == 1
