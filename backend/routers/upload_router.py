"""Training-file upload endpoint (admin-only).

File Security gateway check DISABLED at the explicit, informed request of
the project owner (2026-08-25) - every upload now goes straight to
backend/pipelines/ingest_chroma.py's add_to_kb() with no scan, no
quarantine, no LLM review. This means a genuinely malicious upload (e.g.
a PDF with a real /OpenAction -> /JavaScript payload) is embedded into the
knowledge base unfiltered - verified working before this change via a
crafted test PDF (real /JavaScript+/JS+/OpenAction markers correctly
triggered the deterministic floor -> BLOCK -> quarantine -> verified,
never ingested).

To restore the check: route through security_gateway.gateway.analyze(
"file_security", ...) again before calling add_to_kb(), as
skills/files/malicious-pdf/SKILL.md and CLAUDE.md section 4.7 describe -
see git history for this file's prior version.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status

import auth
from common import security_db
import webapp_db as db
from pipelines.ingest_chroma import SUPPORTED_EXTENSIONS, add_to_kb
from schemas import TrainingFileOut, UploadResponse

router = APIRouter(prefix="/api/upload", tags=["upload"])

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
# Deterministic rate limit - a plain count-and-compare infra-safety
# boundary (CLAUDE.md section 8), not an LLM judgment call, same category
# as MAX_FILE_SIZE. Tracked in-process (see security_gateway/mcp_tools/
# redis_tool.py's record_attempt/get_attempt_count - a single uvicorn
# worker process, documented there).
MAX_UPLOADS_PER_WINDOW = 10
RATE_LIMIT_WINDOW_SECONDS = 600


@router.post("", response_model=UploadResponse)
async def upload_training_file(request: Request, file: UploadFile, username: str = Depends(auth.require_admin)):
    from security_gateway.mcp_tools import redis_tool

    raw = await file.read()
    if len(raw) > MAX_FILE_SIZE:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File too large (max 20MB)")

    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                             f"Unsupported file type '{ext}'. Supported: {sorted(SUPPORTED_EXTENSIONS)}")

    recent = redis_tool.get_attempt_count(f"upload:{username}", window_seconds=RATE_LIMIT_WINDOW_SECONDS)
    if recent >= MAX_UPLOADS_PER_WINDOW:
        security_db.log_security_event(agent_id=username, tool_name="upload_training_file",
                                        decision="DENIED_RATE_LIMIT",
                                        detail=f"{recent} uploads in the last {RATE_LIMIT_WINDOW_SECONDS}s")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                             f"Upload rate limit reached ({MAX_UPLOADS_PER_WINDOW} per "
                             f"{RATE_LIMIT_WINDOW_SECONDS // 60} minutes) - try again shortly.")
    redis_tool.record_attempt(f"upload:{username}")

    # File Security gateway check intentionally skipped here - see module
    # docstring. Every file that passes the extension/size checks above is
    # ingested unconditionally, with no scan and no quarantine.
    ingest_result = add_to_kb(file.filename, raw, uploaded_by=username)
    db.record_training_file(file.filename, len(raw), username)

    return UploadResponse(filename=file.filename, chunks_ingested=ingest_result["chunks"],
                           document_id=ingest_result["document_id"], trust_status="trusted")


@router.get("/history", response_model=list[TrainingFileOut])
def training_history(_username: str = Depends(auth.require_admin)):
    return db.list_training_files()
