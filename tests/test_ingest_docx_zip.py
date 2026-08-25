import io
import zipfile

from pipelines.ingest_chroma import SUPPORTED_EXTENSIONS, _archive_safe_to_extract, extract_text_sample


def _make_zip(entries: dict, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_docx_and_zip_are_supported_extensions():
    assert ".docx" in SUPPORTED_EXTENSIONS
    assert ".zip" in SUPPORTED_EXTENSIONS


def test_extract_text_sample_from_docx():
    raw = _make_zip({"word/document.xml":
                      "<w:document><w:body><w:p>Rotate credentials every 90 days.</w:p></w:body></w:document>"})
    text = extract_text_sample("policy.docx", raw)
    assert "Rotate credentials every 90 days" in text


def test_extract_text_sample_from_zip_of_markdown():
    raw = _make_zip({"notes.md": "Incident response runbook contents here."})
    text = extract_text_sample("bundle.zip", raw)
    assert "Incident response runbook" in text


def test_extract_text_sample_skips_unsafe_archive():
    raw = _make_zip({"a.txt": "A" * 5_000_000})  # will exceed the safety ratio cap
    assert _archive_safe_to_extract(raw) is False
    text = extract_text_sample("bomb.zip", raw)
    assert text == ""  # never decompressed


def test_extract_text_sample_safe_docx_extracts_normally():
    raw = _make_zip({"word/document.xml": "<w:document><w:body>hello</w:body></w:document>"})
    assert _archive_safe_to_extract(raw) is True
    text = extract_text_sample("hello.docx", raw)
    assert "hello" in text
