"""Sandbox MCP tool: real local quarantine storage for MITIGATE/BLOCK
evidence - "Sandbox" in the architecture diagram's MCP Tools box.

Two kinds of evidence:
- "text": a chat question + retrieved context that was refused/flagged
  (rag_security) - stored directly in security_db.sandbox_items.content.
- "file": an uploaded file that was held instead of ingested
  (file_security) - the ORIGINAL bytes are written under sandbox/ on disk
  (never into the Chroma vector store), with metadata + an extracted text
  sample recorded in security_db so an admin can review without needing
  filesystem access.

Nothing sandboxed here is ever embedded or made retrievable - this is a
holding area, not a degraded/limited version of the knowledge base.
"""
import os
import uuid

from common import security_db

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SANDBOX_DIR = os.path.join(_PROJECT_ROOT, "sandbox")

security_db.init_db()
os.makedirs(SANDBOX_DIR, exist_ok=True)


def quarantine_text(category: str, identity: str, content: str, metadata: dict = None) -> str:
    sandbox_id = f"sbx_{uuid.uuid4().hex[:12]}"
    security_db.sandbox_put(sandbox_id, category=category, identity=identity, kind="text",
                             content=content, metadata=metadata or {})
    return sandbox_id


def quarantine_file(category: str, identity: str, filename: str, raw: bytes,
                     text_sample: str, metadata: dict = None) -> str:
    sandbox_id = f"sbx_{uuid.uuid4().hex[:12]}"
    safe_name = f"{sandbox_id}_{os.path.basename(filename)}"
    disk_path = os.path.join(SANDBOX_DIR, safe_name)
    with open(disk_path, "wb") as f:
        f.write(raw)

    meta = dict(metadata or {})
    meta.update({"filename": filename, "disk_path": disk_path, "size": len(raw)})
    security_db.sandbox_put(sandbox_id, category=category, identity=identity, kind="file",
                             content=text_sample, metadata=meta)
    return sandbox_id


def get(sandbox_id: str):
    return security_db.sandbox_get(sandbox_id)


def list_sandboxed(released: bool = False) -> list:
    return security_db.sandbox_list(released=released)


def release(sandbox_id: str) -> bool:
    """Marks a sandboxed item reviewed/released. Does NOT re-ingest a file
    into the knowledge base automatically - an admin who decides a
    sandboxed file was actually safe re-uploads it normally, which routes
    back through the File Security check exactly like any other upload.
    This just clears it off the "needs review" list."""
    item = security_db.sandbox_get(sandbox_id)
    if item is None:
        return False
    security_db.sandbox_release(sandbox_id)
    return True
