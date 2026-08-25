---
skill_id: archive-bomb
name: Archive (Zip) Bomb Detection
category: files
version: 1.0.0
owner_agent: security_gateway.file_security
implementation: security_gateway/archive_scan.py, security_gateway/gateway.py
---

# What security task is being performed

A resource-exhaustion attack disguised as a document upload: a small
compressed file that expands to an enormous size (or nests archives
within archives) when decompressed, intended to exhaust disk/memory
during extraction. Applies to `.zip` uploads directly, and as
defense-in-depth to `.docx`/`.xlsx` (also zip-structured internally) via
the same `archive_scan.py::scan_zip_structure` check `malicious-docx`
uses for macro detection.

# How the agent should investigate

This is the one file-security skill where the deterministic signal is
strong enough to matter more than the LLM's text-based judgment - a
compression ratio in the thousands has no legitimate document use case.
The discussion still runs (for auditability/consistency with every other
skill), but `detection.yaml`'s `floor` is deliberately aggressive here.

# What evidence should be collected

`compression_ratio` (uncompressed / compressed size),
`entry_count`, `max_nested_depth` -
`security_gateway/archive_scan.py::scan_zip_structure`, computed on the
raw upload bytes BEFORE any extraction is attempted for text sampling
(the scan itself only reads zip *metadata* - entry sizes/names - never
decompresses entry contents, so computing this evidence is itself safe
even against a genuine bomb).

# What security boundaries apply

- `detection.yaml`'s `floor`: `compression_ratio >= 100` OR
  `entry_count >= 5000` forces BLOCK - a real security-boundary
  deterministic control (CLAUDE.md section 8's "hardcoded deterministic
  controls are allowed only for security boundaries and infrastructure
  safety"), not a judgment call.
- Because of the floor above, this skill can reach BLOCK without the LLM
  discussion needing to agree - the discussion's own proposed action is
  still logged for audit, but `security_gateway/detection.py`'s floor
  enforcement overrides it upward, never downward.

# How the result should be verified

Same sandbox re-read pattern as the other `files/*` skills, plus a
confirmation that the file's entries were never actually extracted
(`backend/pipelines/ingest_chroma.py`'s zip loader only reads entries
after the gateway has already ALLOWed the upload).

# MCP Tools

`quarantine_document` (auto-executed) is the practically relevant one -
the floor above already forces BLOCK before the LLM's tool proposals are
even reachable in the common case, so `remove_vector` rarely applies
here (a genuine bomb is never ingested in the first place).
