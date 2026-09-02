---
skill_id: malicious-pdf
name: Malicious Document Detection (PDF and general text)
category: files
version: 2.0.0
owner_agent: security_gateway.file_security
implementation: security_gateway/gateway.py, security_gateway/mcp_tools/sandbox_tool.py
---

# What security task is being performed

Despite the name (matched to the architecture diagram's original
"malicious_pdf" skill), this is the default/general document-injection
check for every upload extension that doesn't have its own more
specialized skill - `.pdf`, `.md`, `.txt`, `.xlsx` all fall through to
this skill (`detection.yaml`'s `default: true`, the Supervisor Agent's
fallback once `.docx`/`.zip`'s own routing rules don't match); those two
route to `malicious-docx`/`archive-bomb` instead, which handle their
format-specific active-payload risks. Every uploaded document is checked
here before it can be embedded into the RAG knowledge base - the
ingestion-time half of RAG poisoning defense; `rag/rag-poisoning` is the
query-time half.

# How the agent should investigate

Deterministic evidence gathered BEFORE the LLM reasons (CLAUDE.md:
"evidence, not verdict"): for PDFs specifically, a raw byte-level scan for
`/JavaScript`, `/JS`, `/OpenAction`, `/AA` markers - real PDF-object-level
indicators of an active payload. For all extensions, the extracted text
sample is read for injection-style instructions aimed at whichever LLM
later reads this document as trusted context, exactly like
`rag-poisoning`'s check but at ingestion time. A PDF flagged for active
content markers should weigh toward MITIGATE/BLOCK even if the extracted
text reads as benign - an active payload doesn't need injected text to be
dangerous.

# What evidence should be collected

`pdf_active_content_markers` / `pdf_marker_count`, `text_sample`,
`extension`, `size_bytes`. `search_threat_knowledge("malicious document
indirect prompt injection")`.

**2026-08-26: per-chunk evidence, a second call site.** After the
whole-file check above ALLOWs a document, `backend/pipelines/
ingest_chroma.py` chunks it (as it always did) and now ALSO scores each
individual chunk's text via `security_gateway/chunk_scan.py` - a real,
pre-trained prompt-injection classifier
(`protectai/deberta-v3-base-prompt-injection-v2`, HuggingFace
`transformers`), not a hand-picked keyword/phrase list. This is the
"ML" signal. Any chunk scoring at/above the LOW band gets its own
`gateway.analyze("file_security", ...)` call, with `chunk_injection_score`
as an extra evidence field alongside `context_has_imperative_language`
(the same regex signal `rag/rag-poisoning` already defines - reused, not
duplicated). This is genuinely PER-CHUNK: one poisoned chunk in an
otherwise-legitimate document is quarantined by itself
(`sandbox_tool.quarantine_text`, tagged with filename + chunk index) -
every other chunk still gets embedded normally. The whole-file byte/
structure check above is unaffected and still runs first; a chunk-level
finding never rejects the whole upload the way a whole-file BLOCK does.

# What security boundaries apply

- `detection.yaml`'s `floor` (list, most-restrictive match wins):
  `pdf_marker_count >= 2` forces a minimum of MITIGATE on the whole-file
  byte-scan path - two or more active-content markers together is a
  strong enough deterministic signal to never leave to model judgment
  alone. `chunk_injection_score >= 0.75` forces the same minimum on the
  per-chunk ML-classifier path, independently.
- ALLOW: ingested normally. MITIGATE/BLOCK: sandboxed, never embedded -
  at chunk granularity when the finding came from the per-chunk path,
  at whole-file granularity when it came from the byte/structure scan.

# How the result should be verified

`sandbox_tool.list_sandboxed()` re-read to confirm the item is actually
present, plus a direct Chroma count-by-`document_id` check confirming a
BLOCKed file's chunks were never added.

# MCP Tools

- `get_document_provenance` - risk low, auto-executed, read-only.
- `quarantine_document` - risk medium, auto-executed (explicit proposal
  alongside the automatic policy-driven sandbox effect).
- `remove_vector` - risk high, **requires admin approval**. Only
  meaningful once a `document_id` exists (i.e. the file was already
  ingested by an earlier, less strict check before this one caught it on
  re-scan) - a brand-new upload has no vectors yet to remove.
