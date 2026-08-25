import os

from common import security_db
from security_gateway.mcp_tools import sandbox_tool


def test_quarantine_text_and_get(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()

    sandbox_id = sandbox_tool.quarantine_text("rag_security", "alice", "Q: bad question\nContext: ...",
                                                metadata={"action": "BLOCK"})
    item = sandbox_tool.get(sandbox_id)
    assert item is not None
    assert item["kind"] == "text"
    assert item["category"] == "rag_security"
    assert item["metadata"]["action"] == "BLOCK"


def test_quarantine_file_writes_to_disk_and_never_ingested(monkeypatch, temp_sqlite_path, tmp_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    monkeypatch.setattr(sandbox_tool, "SANDBOX_DIR", str(tmp_path))
    security_db.init_db()

    raw = b"malicious content here"
    sandbox_id = sandbox_tool.quarantine_file("file_security", "bob", "evil.md", raw,
                                                text_sample="malicious content here",
                                                metadata={"action": "MITIGATE"})
    item = sandbox_tool.get(sandbox_id)
    assert item["kind"] == "file"
    disk_path = item["metadata"]["disk_path"]
    assert os.path.exists(disk_path)
    with open(disk_path, "rb") as f:
        assert f.read() == raw


def test_list_sandboxed_and_release(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()

    sid = sandbox_tool.quarantine_text("file_security", "carol", "content", metadata={})
    assert len(sandbox_tool.list_sandboxed(released=False)) == 1

    assert sandbox_tool.release(sid) is True
    assert sandbox_tool.list_sandboxed(released=False) == []
    assert len(sandbox_tool.list_sandboxed(released=True)) == 1


def test_release_unknown_id_returns_false(monkeypatch, temp_sqlite_path):
    monkeypatch.setattr(security_db, "DB_PATH", temp_sqlite_path)
    security_db.init_db()
    assert sandbox_tool.release("sbx_does_not_exist") is False
