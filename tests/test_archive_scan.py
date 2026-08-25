import io
import zipfile

from security_gateway import archive_scan


def _make_zip(entries: dict, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_is_zip_true_for_real_zip():
    raw = _make_zip({"a.txt": "hello"})
    assert archive_scan.is_zip(raw) is True


def test_is_zip_false_for_plain_text():
    assert archive_scan.is_zip(b"not a zip at all") is False


def test_scan_zip_structure_basic_counts():
    raw = _make_zip({"a.txt": "hello", "b.txt": "world"})
    info = archive_scan.scan_zip_structure(raw)
    assert info["is_zip"] is True
    assert info["entry_count"] == 2
    assert info["macro_present"] is False


def test_scan_zip_structure_detects_macro():
    raw = _make_zip({"word/document.xml": "<doc/>", "word/vbaProject.bin": "macro"})
    info = archive_scan.scan_zip_structure(raw)
    assert info["macro_present"] is True


def test_scan_zip_structure_high_ratio_for_repetitive_content():
    raw = _make_zip({"a.txt": "A" * 2_000_000})
    info = archive_scan.scan_zip_structure(raw)
    assert info["compression_ratio"] > 50


def test_scan_zip_structure_non_zip_returns_safe_defaults():
    info = archive_scan.scan_zip_structure(b"just plain text content")
    assert info["is_zip"] is False
    assert info["compression_ratio"] == 0.0
    assert info["macro_present"] is False


def test_scan_zip_structure_corrupt_zip_flagged():
    corrupt = b"PK\x03\x04" + b"\x00" * 50  # zip magic bytes, garbage body
    info = archive_scan.scan_zip_structure(corrupt)
    assert info.get("corrupt") is True


def test_extract_zip_text_entries_only_reads_text_extensions():
    raw = _make_zip({"notes.md": "hello world", "image.png": b"\x89PNG binary junk"})
    text = archive_scan.extract_zip_text_entries(raw)
    assert "hello world" in text
    assert "PNG" not in text
