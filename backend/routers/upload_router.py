"""Training-file upload endpoint (admin-only).

Two-stage security check (2026-08-26, re-enabled + made chunk-granular
at explicit request - the 2026-08-25 whole-file-only version is in git
history):

1. WHOLE-FILE check (security_gateway.gateway.analyze("file_security",
   ...) over the file's raw bytes/structure - PDF active-content
   markers, zip/archive-bomb/macro structure, skills/files/*). A
   MITIGATE/BLOCK here rejects the ENTIRE upload (sandboxed) - a
   structural/active-payload threat (a zip bomb, a JS-laced PDF) is a
   property of the whole file, not something to partially salvage.
2. PER-CHUNK check, only reached if stage 1 ALLOWs: the file is chunked
   (pipelines/ingest_chroma.py::prepare_chunks), each chunk scored by
   embedding similarity to known injection phrasing
   (security_gateway/chunk_scan.py), and any chunk at/above the LOW
   band gets its OWN gateway.analyze("file_security", ...) call. A
   flagged chunk is quarantined individually
   (security_gateway/mcp_tools/sandbox_tool.py, tagged with filename +
   chunk index) - every other chunk from the same document still gets
   embedded. One poisoned paragraph no longer holds an entire otherwise-
   legitimate document hostage.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status

import auth
from common import security_db
import webapp_db as db
from pipelines.ingest_chroma import SUPPORTED_EXTENSIONS, embed_chunks, extract_text_sample, prepare_chunks
from schemas import TrainingFileOut, UploadResponse
from security_gateway import chunk_scan, gateway

router = APIRouter(prefix="/api/upload", tags=["upload"])

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
# Deterministic rate limit - a plain count-and-compare infra-safety
# boundary (CLAUDE.md section 8), not an LLM judgment call, same category
# as MAX_FILE_SIZE. Tracked in-process (see security_gateway/mcp_tools/
# redis_tool.py's record_attempt/get_attempt_count - a single uvicorn
# worker process, documented there).
MAX_UPLOADS_PER_WINDOW = 10
RATE_LIMIT_WINDOW_SECONDS = 600


async def _scan_and_embed_chunks(filename: str, chunks: list, uploaded_by: str, request: Request) -> dict:
    """Stage 2 - per-chunk scan. Returns {"embedded": int, "quarantined_ids": [str, ...]}."""
    from security_gateway.mcp_tools import sandbox_tool

    if not chunks:
        return {"embedded": 0, "quarantined_ids": []}

    texts = [c.page_content for c in chunks]
    scores = chunk_scan.score_chunks(texts)

    clean, quarantined_ids = [], []
    for i, (chunk, score) in enumerate(zip(chunks, scores)):
        if score < chunk_scan.LOW_MAX:
            clean.append(chunk)
            continue

        evidence = gateway.gather_chunk_security_evidence(
            filename=filename, chunk_text=chunk.page_content, chunk_index=i,
            injection_score=score, uploaded_by=uploaded_by,
        )
        result = await gateway.analyze(
            "file_security", uploaded_by, evidence,
            sandbox_payload={"kind": "text", "content": chunk.page_content},
            log=request.app.state.log,
        )
        if result.action == "ALLOW":
            clean.append(chunk)
            continue

        # MITIGATE/BLOCK: quarantine THIS chunk only - sandbox_tool already
        # ran via gateway.analyze's own effect handling for MITIGATE/BLOCK's
        # sandbox_no_ingest/reject_and_sandbox effects, but that quarantines
        # the evidence gateway.py logs (the chunk text), not a chunk-scan-
        # specific record - tag chunk_index/injection_score explicitly here
        # so the Admin Dashboard can show which chunk of which file.
        sandbox_id = sandbox_tool.quarantine_text(
            "file_security", uploaded_by, chunk.page_content,
            metadata={"filename": filename, "chunk_index": i, "injection_score": score,
                      "reasoning": result.reasoning, "action": result.action, "per_chunk": True,
                      "document_id": chunk.metadata.get("document_id")},
        )
        quarantined_ids.append(sandbox_id)

    embedded = embed_chunks(clean)
    return {"embedded": embedded, "quarantined_ids": quarantined_ids}


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

    try:
        text_sample = extract_text_sample(file.filename, raw)
    except Exception as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Could not read file: {e}")

    # --- Stage 1: whole-file structural/active-content check ---
    evidence = gateway.gather_file_security_evidence(
        filename=file.filename, raw=raw, text_sample=text_sample,
        uploaded_by=username, recent_uploads_by_uploader=recent,
    )
    result = await gateway.analyze(
        "file_security", username, evidence,
        sandbox_payload={"kind": "file", "filename": file.filename, "raw": raw, "text_sample": text_sample},
        log=request.app.state.log,
    )

    if result.action == "BLOCK":
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                             f"Upload rejected by the security gateway: {result.reasoning}")

    if result.action == "MITIGATE":
        return UploadResponse(filename=file.filename, chunks_ingested=0, document_id=None,
                               trust_status="sandboxed")

    # --- Stage 2: per-chunk embedding-similarity scan ---
    prepared = prepare_chunks(file.filename, raw, uploaded_by=username)
    scan_result = await _scan_and_embed_chunks(file.filename, prepared["chunks"], username, request)

    db.record_training_file(file.filename, len(raw), username)

    trust_status = "trusted" if not scan_result["quarantined_ids"] else "partially_quarantined"
    return UploadResponse(
        filename=file.filename, chunks_ingested=scan_result["embedded"],
        document_id=prepared["document_id"], trust_status=trust_status,
        chunks_quarantined=len(scan_result["quarantined_ids"]),
        quarantined_chunk_ids=scan_result["quarantined_ids"],
    )


@router.get("/history", response_model=list[TrainingFileOut])
def training_history(_username: str = Depends(auth.require_admin)):
    return db.list_training_files()
