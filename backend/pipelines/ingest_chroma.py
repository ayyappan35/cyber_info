"""The ingestion pipeline: load a document (pdf/xlsx/md/txt), extract its
text, chunk it, and add it into the cyber_defense_kb Chroma collection.

Text extraction (extract_text_sample) and embedding (add_to_kb) are now
two separate steps, not one call - backend/routers/upload_router.py
extracts text first, runs it past
security_gateway.gateway.analyze(category="file_security", ...), and only
calls add_to_kb() if the gateway's decision is ALLOW. A file that is
MITIGATEd/BLOCKed is never embedded - see skills/malicious_pdf/SKILL.md.
This is the ingestion-time enforcement point; there is no separate
trust_status/quarantine bookkeeping to reconcile afterward, because a
document is only ever added here once it has already been approved.
"""
import io
import os
import re
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from typing import List

import pymupdf as fitz  # `import fitz` prints a deprecation notice to
# stdout - importing as pymupdf avoids corrupting any stdio-framed process
# that imports this module.

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from rag_search import get_vectorstore

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from security_gateway.archive_scan import extract_zip_text_entries, is_zip, scan_zip_structure

SUPPORTED_EXTENSIONS = {".pdf", ".xlsx", ".md", ".txt", ".docx", ".zip"}

_XML_TAG_RE = re.compile(r"<[^>]+>")

# A hard infra-safety cap (CLAUDE.md section 8), independent of
# files/archive-bomb/detection.yaml's LLM-facing floor thresholds (100x
# ratio / 5000 entries) - this guard runs BEFORE the gateway check even
# sees the upload (extract_text_sample builds the gateway's own evidence),
# so it can't rely on the floor having fired yet. Anything failing this
# check never gets its contents decompressed at all - text_sample is left
# empty and the gateway's structural evidence (compression_ratio,
# entry_count from scan_zip_structure's metadata-only read) is what the
# LLM discussion and floor act on instead.
_MAX_SAFE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
_MAX_SAFE_RATIO = 300


def _archive_safe_to_extract(raw: bytes) -> bool:
    if not is_zip(raw):
        return True
    info = scan_zip_structure(raw)
    if info.get("corrupt") or info["entry_count"] < 0:
        return False
    return info["uncompressed_size"] <= _MAX_SAFE_UNCOMPRESSED_BYTES and info["compression_ratio"] <= _MAX_SAFE_RATIO


def _load_pdf(filename: str, raw: bytes) -> List[Document]:
    docs = []
    pdf = fitz.open(stream=io.BytesIO(raw), filetype="pdf")

    for page_no, page in enumerate(pdf, start=1):
        text = page.get_text("text")
        if text.strip():
            docs.append(Document(
                page_content=text,
                metadata={"source": filename, "page": page_no, "content_type": "pdf_text"},
            ))

        try:
            for table in page.find_tables():
                table_data = table.extract()
                table_text = "\n".join(
                    " | ".join(str(cell) if cell else "" for cell in row) for row in table_data
                )
                if table_text.strip():
                    docs.append(Document(
                        page_content=table_text,
                        metadata={"source": filename, "page": page_no, "content_type": "pdf_table"},
                    ))
        except Exception:
            pass

    return docs


def _load_xlsx(filename: str, raw: bytes) -> List[Document]:
    import pandas as pd  # lazy: xlsx support is optional, pdf/md/txt shouldn't need it installed

    docs = []
    sheets = pd.read_excel(io.BytesIO(raw), sheet_name=None)

    for sheet_name, df in sheets.items():
        docs.append(Document(
            page_content=df.to_markdown(index=False),
            metadata={"source": filename, "sheet_name": sheet_name, "content_type": "xlsx_table"},
        ))

    return docs


def _load_text(filename: str, raw: bytes) -> List[Document]:
    text = raw.decode("utf-8", errors="ignore")
    return [Document(page_content=text, metadata={"source": filename, "content_type": "text"})]


def _load_docx(filename: str, raw: bytes) -> List[Document]:
    """Stdlib-only extraction: a .docx is a zip whose visible text lives in
    word/document.xml as OOXML markup - strips tags rather than pulling in
    python-docx as a new dependency. Deliberately does NOT read
    word/vbaProject.bin (macro code) - that entry's mere PRESENCE is
    files/malicious-docx's evidence signal (security_gateway/archive_scan.py),
    never its content."""
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        try:
            xml = zf.read("word/document.xml").decode("utf-8", errors="ignore")
        except KeyError:
            return []
    text = _XML_TAG_RE.sub(" ", xml)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []
    return [Document(page_content=text, metadata={"source": filename, "content_type": "docx_text"})]


def _load_zip(filename: str, raw: bytes) -> List[Document]:
    """Only ever reached after the File Security gateway check has already
    ALLOWed this upload (the archive-bomb floor runs on zip METADATA before
    this - see security_gateway/archive_scan.py::scan_zip_structure).
    Extracts text from .md/.txt entries only; other entry types are
    skipped, not decompressed."""
    text = extract_zip_text_entries(raw, max_chars=1_000_000)
    if not text.strip():
        return []
    return [Document(page_content=text, metadata={"source": filename, "content_type": "zip_text"})]


def _load(filename: str, raw: bytes) -> List[Document]:
    ext = os.path.splitext(filename)[1].lower()
    if ext in (".docx", ".zip", ".xlsx") and not _archive_safe_to_extract(raw):
        # Never decompress a structurally-unsafe zip-based upload, even to
        # sample its text - the gateway's file_security check (and
        # files/archive-bomb's floor) still runs on scan_zip_structure's
        # metadata-only evidence and can BLOCK it; this just means no text
        # content is ever actually decompressed to produce that evidence.
        return []
    if ext == ".pdf":
        return _load_pdf(filename, raw)
    if ext == ".xlsx":
        return _load_xlsx(filename, raw)
    if ext in (".md", ".txt"):
        return _load_text(filename, raw)
    if ext == ".docx":
        return _load_docx(filename, raw)
    if ext == ".zip":
        return _load_zip(filename, raw)
    raise ValueError(f"Unsupported file type '{ext}'. Supported: {sorted(SUPPORTED_EXTENSIONS)}")


def extract_text_sample(filename: str, raw: bytes, max_chars: int = 4000) -> str:
    """Extracts text without embedding anything - used to build the
    File Security gateway check's evidence before any ingestion decision
    is made. See _archive_safe_to_extract - a zip-based upload structurally
    unsafe to decompress yields an empty sample here, not a crash or a
    real decompression attempt."""
    docs = _load(filename, raw)
    return "\n\n".join(d.page_content for d in docs)[:max_chars]


def add_to_kb(filename: str, raw: bytes, uploaded_by: str = "", category: str = "",
              origin: str = "upload") -> dict:
    """Chunks and embeds a file into cyber_defense_kb. Only ever called
    after a File Security gateway ALLOW - see this module's docstring.
    Returns {"document_id", "chunks"}; chunks=0 (document_id=None) if the
    file produced no extractable text."""
    docs = _load(filename, raw)
    if not docs:
        return {"document_id": None, "chunks": 0}

    document_id = uuid.uuid4().hex
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    provenance = f"{origin}:{uploaded_by or category or 'unknown'}"

    for d in docs:
        if uploaded_by:
            d.metadata["uploaded_by"] = uploaded_by
        if category:
            d.metadata["category"] = category
        d.metadata.update({
            "document_id": document_id, "origin": origin,
            "timestamp": timestamp, "provenance": provenance,
        })

    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
    chunks = splitter.split_documents(docs)
    for i, chunk in enumerate(chunks):
        chunk.metadata["chunk_id"] = f"{document_id}:{i}"

    get_vectorstore().add_documents(chunks)
    return {"document_id": document_id, "chunks": len(chunks)}


def ingest_files(file_paths: List[str], category: str = "", origin: str = "seed") -> int:
    """Ingest a batch of local, already-trusted files by path (CLI /
    offline use, e.g. seed_knowledge.py for knowledge/*.md) - no gateway
    check, matching origin="seed"'s meaning: first-party curated content,
    never user-supplied."""
    total = 0
    for path in file_paths:
        with open(path, "rb") as f:
            raw = f.read()
        result = add_to_kb(os.path.basename(path), raw, category=category, origin=origin)
        print(f"  {path}: {result['chunks']} chunks (document_id={result['document_id']})")
        total += result["chunks"]
    return total


if __name__ == "__main__":
    import sys
    from rag_search import DB_DIR, COLLECTION_NAME

    paths = sys.argv[1:]
    if not paths:
        print(f"Usage: python backend/pipelines/ingest_chroma.py <file1> [file2 ...]")
        print(f"Supported types: {sorted(SUPPORTED_EXTENSIONS)}")
        print(f"Target collection: {COLLECTION_NAME} @ {DB_DIR}")
        sys.exit(1)

    total = ingest_files(paths)
    print(f"Ingested {total} chunks total into '{COLLECTION_NAME}'.")
