from common import security_db
from security_gateway import chain_detection


def _patch(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()


def test_no_chain_for_single_skill(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    security_db.log_gateway_decision(category="file_security", identity="mallory", action="MITIGATE",
                                      raw_action="MITIGATE", confidence=0.7, threat_indicators=[],
                                      reasoning="", enforced=True, skill_ids=["malicious-pdf"])
    result = chain_detection.detect_chain("mallory")
    assert result["chained"] is False


def test_no_chain_for_repeated_same_skill(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    for _ in range(3):
        security_db.log_gateway_decision(category="authentication", identity="mallory", action="MITIGATE",
                                          raw_action="MITIGATE", confidence=0.7, threat_indicators=[],
                                          reasoning="", enforced=True, skill_ids=["brute-force"])
    result = chain_detection.detect_chain("mallory")
    assert result["chained"] is False


def test_chain_detected_across_distinct_skills(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    security_db.log_gateway_decision(category="file_security", identity="mallory", action="MITIGATE",
                                      raw_action="MITIGATE", confidence=0.7, threat_indicators=[],
                                      reasoning="", enforced=True, skill_ids=["malicious-pdf"])
    security_db.log_gateway_decision(category="rag_security", identity="mallory", action="BLOCK",
                                      raw_action="BLOCK", confidence=0.9, threat_indicators=[],
                                      reasoning="", enforced=True, skill_ids=["jailbreak", "prompt-injection"])
    result = chain_detection.detect_chain("mallory")
    assert result["chained"] is True
    assert "malicious-pdf" in result["skill_ids"]
    assert "jailbreak" in result["skill_ids"]
    assert sorted(result["categories"]) == ["file_security", "rag_security"]


def test_allow_decisions_never_count_toward_a_chain(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    security_db.log_gateway_decision(category="file_security", identity="clean_user", action="ALLOW",
                                      raw_action="ALLOW", confidence=0.9, threat_indicators=[],
                                      reasoning="", enforced=True, skill_ids=["malicious-pdf"])
    security_db.log_gateway_decision(category="rag_security", identity="clean_user", action="ALLOW",
                                      raw_action="ALLOW", confidence=0.9, threat_indicators=[],
                                      reasoning="", enforced=True, skill_ids=["rag-poisoning"])
    result = chain_detection.detect_chain("clean_user")
    assert result["chained"] is False


def test_chain_scoped_to_window(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    # Directly inserted with an old timestamp (rather than relying on
    # wall-clock timing at second-level precision, which a window_seconds=0
    # test can't reliably distinguish) - simulates a decision from well
    # outside any reasonable chain window.
    conn = security_db._conn()
    conn.execute(
        "INSERT INTO gateway_decisions (ts, category, identity, action, raw_action, confidence, "
        "threat_indicators, reasoning, enforced, skill_ids) VALUES "
        "('2020-01-01T00:00:00+00:00', 'file_security', 'mallory', 'MITIGATE', 'MITIGATE', 0.7, '[]', "
        "'', 1, '[\"malicious-pdf\"]')"
    )
    conn.commit()
    conn.close()
    security_db.log_gateway_decision(category="rag_security", identity="mallory", action="BLOCK",
                                      raw_action="BLOCK", confidence=0.9, threat_indicators=[],
                                      reasoning="", enforced=True, skill_ids=["jailbreak"])
    result = chain_detection.detect_chain("mallory", window_seconds=1800)
    assert result["chained"] is False


def test_chain_scoped_to_identity(monkeypatch, temp_sqlite_path):
    _patch(monkeypatch, temp_sqlite_path)
    security_db.log_gateway_decision(category="file_security", identity="mallory", action="MITIGATE",
                                      raw_action="MITIGATE", confidence=0.7, threat_indicators=[],
                                      reasoning="", enforced=True, skill_ids=["malicious-pdf"])
    security_db.log_gateway_decision(category="rag_security", identity="someone_else", action="BLOCK",
                                      raw_action="BLOCK", confidence=0.9, threat_indicators=[],
                                      reasoning="", enforced=True, skill_ids=["jailbreak"])
    assert chain_detection.detect_chain("mallory")["chained"] is False
    assert chain_detection.detect_chain("someone_else")["chained"] is False
