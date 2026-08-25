"""Real zip-structure inspection shared by files/malicious-docx (macro
presence) and files/archive-bomb (compression-ratio/entry-count) - both
`.docx`/`.xlsx` (OOXML, zip-based) and a plain `.zip` upload go through
this. Deliberately reads only zip METADATA (entry names, compressed/
uncompressed sizes from the central directory) - never decompresses entry
CONTENTS - so computing this evidence is itself safe to run even against
a genuine zip bomb, before any text extraction is attempted.
"""
import io
import zipfile


def is_zip(raw: bytes) -> bool:
    return raw[:4] == b"PK\x03\x04" or raw[:4] == b"PK\x05\x06"


def scan_zip_structure(raw: bytes) -> dict:
    """Returns {"is_zip", "entry_count", "compressed_size",
    "uncompressed_size", "compression_ratio", "macro_present"}.
    compression_ratio is uncompressed/compressed (guarded against
    division by zero); macro_present checks for a `word/vbaProject.bin`
    entry name specifically (the real, standard location for an embedded
    VBA macro project in OOXML documents) - never opened/read, only the
    entry's NAME is checked."""
    if not is_zip(raw):
        return {"is_zip": False, "entry_count": 0, "compressed_size": 0,
                "uncompressed_size": 0, "compression_ratio": 0.0, "macro_present": False}

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            infos = zf.infolist()
    except zipfile.BadZipFile:
        # Malformed/corrupt zip claiming a PK magic header - treated as
        # maximally suspicious evidence (fed to the LLM discussion), not
        # silently ignored.
        return {"is_zip": True, "entry_count": -1, "compressed_size": 0,
                "uncompressed_size": 0, "compression_ratio": 0.0, "macro_present": False,
                "corrupt": True}

    entry_count = len(infos)
    compressed_size = sum(i.compress_size for i in infos)
    uncompressed_size = sum(i.file_size for i in infos)
    ratio = (uncompressed_size / compressed_size) if compressed_size > 0 else float(uncompressed_size > 0) * 1e9
    macro_present = any(i.filename == "word/vbaProject.bin" for i in infos)

    return {
        "is_zip": True,
        "entry_count": entry_count,
        "compressed_size": compressed_size,
        "uncompressed_size": uncompressed_size,
        "compression_ratio": round(ratio, 2),
        "macro_present": macro_present,
    }


def extract_zip_text_entries(raw: bytes, extensions: tuple = (".md", ".txt"), max_chars: int = 4000) -> str:
    """Reads text CONTENT only from a zip's .md/.txt entries - only ever
    called after the archive-bomb gateway check has already ALLOWed the
    upload (backend/pipelines/ingest_chroma.py's zip loader), never before."""
    texts = []
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for info in zf.infolist():
            if info.filename.lower().endswith(extensions):
                with zf.open(info) as f:
                    texts.append(f.read().decode("utf-8", errors="ignore"))
    return "\n\n".join(texts)[:max_chars]
