# Cyber Defense Assistant — AI Security Gateway

A SOC-analyst chat/RAG web app protected by a single **AI Security
Gateway**: every login, chat question, and document upload is routed
through a Threat Router to a category-specific security skill, reasoned
about by a real local LLM (Ollama), and enforced by a deterministic
policy layer before anything happens.

```
                         USER / REQUEST
                              |
                              v
                    AI SECURITY GATEWAY (security_gateway/gateway.py)
                              |
                       Threat Router (threat_router.py)
                              |
        +----------------------+----------------------+
        |                      |                       |
        v                      v                       v
  Authentication          RAG Security             File Security
 (login attempts)      (chat questions)          (admin uploads)
        |                      |                       |
  skills/brute_force/   skills/rag_poisoning/   skills/malicious_pdf/
     SKILL.md               SKILL.md                SKILL.md
        |                      |                       |
        +----------------------+----------------------+
                              |
                              v
                    Security LLM Discussion (llm_discussion.py)
                    -> real Ollama call, structured JSON output
                              |
                      SECURITY DECISION (decision.py)
                              |
                +-------------+--------------+
                v             v              v
             ALLOW        MITIGATE         BLOCK
                              |
                              v
                MCP Tools (security_gateway/mcp_tools/)
              redis_tool  ·  siem_tool  ·  sandbox_tool
                              |
                        verified (re-read ground truth)
```

## Running it

Requires [Ollama](https://ollama.com/) running locally with `llama3.2:3b`
pulled (`ollama pull llama3.2:3b`).

```bash
# one-time: seed knowledge/*.md into the RAG knowledge base
python seed_knowledge.py
python seed_threat_knowledge.py   # separate collection the gateway's LLM discussion grounds against

# backend
cd backend
../venv/Scripts/python.exe -m uvicorn main:app --port 8000

# frontend
cd frontend
npm run dev
```

## The three request paths

- **Login** (`POST /api/auth/login`, `backend/routers/auth_router.py`):
  bcrypt/JWT stays plain deterministic code — an LLM never decides if a
  password is correct. The Authentication branch (`skills/brute_force/`)
  reasons about the *pattern* around the attempt (failed-attempt count,
  recent attempt rate, account lock state) and can `BLOCK` further
  attempts from an identity via the Redis/local block list, independent
  of `webapp_db.py`'s own always-on `LOCKOUT_THRESHOLD` account lock.
- **Chat** (`POST /api/query`, `.../stream`,
  `backend/routers/query_router.py`): retrieves from the knowledge base
  (`backend/pipelines/rag_graph_chroma.py`), then the RAG Security branch
  (`skills/rag_poisoning/`) checks BOTH the question and the retrieved
  context together, live, on every message — direct prompt injection and
  indirect injection (a poisoned document trying to hijack the answer)
  are both in scope. Only on `ALLOW`/`MITIGATE` does the answering LLM
  call happen; `BLOCK` returns a fixed refusal with nothing else leaving
  the gateway.
- **Upload** (`POST /api/upload`, admin-only,
  `backend/routers/upload_router.py`): text is extracted first
  (`backend/pipelines/ingest_chroma.py::extract_text_sample`), then the
  File Security branch (`skills/malicious_pdf/`) reasons over a
  deterministic PDF active-content scan (`/JavaScript`, `/OpenAction`,
  etc. byte markers) plus the extracted text. Only `ALLOW` reaches
  `add_to_kb()` and gets embedded — `MITIGATE`/`BLOCK` hold the file in
  the sandbox and it is never ingested.

## Deterministic vs. LLM judgment

`policies/security_gateway_policy.yaml` is the only place that decides
what a proposed action is *allowed* to do (`security_gateway/policy.py`):
which actions are enabled per category, the minimum LLM confidence
required before an action is enforced at full strength (a low-confidence
`BLOCK` is stepped down to `MITIGATE`, never trusted outright), and the
fail-closed action if the Security LLM Discussion node never returns a
schema-valid decision (see `security_gateway/decision.py` -
`SecurityDecision`, Pydantic-validated, never parsed from free text). The
LLM reasons over evidence; it can never edit this file or bypass it.

## MCP Tools

- **`redis_tool.py`** — real `redis.Redis.from_url(...)` when `REDIS_URL`
  is set and the `redis` package is installed; otherwise a working
  SQLite-backed fallback (`security_db.py`) with identical block/expiry
  semantics — never a stub. `backend()` reports which is active.
- **`siem_tool.py`** — thin wrapper over `security_db.py`'s
  `security_events`/`gateway_decisions` tables: a real, queryable,
  persistent security-event log.
- **`sandbox_tool.py`** — real local quarantine storage
  (`sandbox/` on disk for file bytes, `security_db.sandbox_items` for
  metadata/text evidence). Nothing sandboxed is ever embedded or made
  retrievable.

All three are visible in the Admin Dashboard's **Overview** tab
(`GET /api/security/decisions`, `/sandbox`, `/blocked`, `/events`).

## MCP Tool Authorization Gateway and attack chains

The Security LLM Discussion node may also propose specific remediation
tools (`required_tools` in its structured decision) - `security_gateway/
mcp_gateway.py` independently authorizes each one before it runs: tool
must be in the 9-tool catalog, must be scoped to the request's category,
must not be rate-limited, and `risk: critical` tools (`block_ip`,
`terminate_session`, `remove_vector`) queue for admin approval
(`GET/POST /api/security/tool-calls*`) rather than auto-executing. See
`docs/architecture.md` for the full tool catalog and honesty notes on
`require_mfa`/`terminate_session`/`get_ip_reputation`'s real (but
intentionally scoped-down) implementations.

`security_gateway/chain_detection.py` flags when one identity triggers
multiple distinct skills across categories in a 30-minute window (e.g. a
malicious upload followed by a jailbreak chat attempt from the same
account) - `GET /api/security/chain/{identity}`.

## Accounts

No seeded demo account, no hardcoded credential. Every account comes from
`POST /api/auth/signup`. The first account ever created is auto-promoted
to `role='admin'` (bootstrap); every account after that defaults to
`role='user'`. An existing admin can promote/demote from the Users tab.

## Project layout

```
backend/                 FastAPI app: routers, auth, webapp DB, RAG pipelines
  routers/                auth · conversations · query · upload · admin · security
  pipelines/               rag_search.py · rag_graph_chroma.py · ingest_chroma.py · threat_knowledge.py
security_gateway/         The AI Security Gateway
  gateway.py               orchestrates: route -> skill -> LLM discussion -> policy -> MCP tools -> verify
  threat_router.py         category -> skill dispatch
  llm_discussion.py         real Ollama call, structured JSON output, retried + validated
  decision.py               SecurityDecision Pydantic schema
  policy.py                  loads/enforces policies/security_gateway_policy.yaml
  skills.py                  loads skills/*/SKILL.md
  mcp_tools/                redis_tool.py · siem_tool.py · sandbox_tool.py
skills/                   brute_force/ · rag_poisoning/ · malicious_pdf/ (SKILL.md each)
policies/                 security_gateway_policy.yaml
knowledge/                Markdown runbooks (business KB) + cyber_defence/ (threat-knowledge grounding)
frontend/                 React + Vite + Tailwind SPA
security_db.py            SIEM event log, gateway decision log, block list, sandbox store
sandbox/                  Quarantined file bytes on disk
cyberdefense.db           Shared SQLite file (security_db.py's tables + backend/webapp_db.py's tables)
seed_knowledge.py         Ingest knowledge/*.md into the RAG knowledge base
seed_threat_knowledge.py  Ingest knowledge/cyber_defence/*.md into the separate threat-knowledge collection
_archive_2026-08-24_pre_gateway_rebuild/   The prior multi-agent architecture, kept for reference
```

## What changed from the prior architecture (2026-08-24)

This platform was previously a multi-agent LangGraph orchestrator (a
red/blue/governance cyber-range simulation plus per-domain defense agents
- RAG defence, rogue-agent detection, A2A security, etc.). It was
replaced end-to-end with the single AI Security Gateway pipeline above, at
the user's explicit request to rebuild around a specific new architecture
diagram. The old code is preserved, not deleted, under
`_archive_2026-08-24_pre_gateway_rebuild/` in case anything there is
still wanted. The rebuild deliberately narrowed scope to exactly the three
request paths this app actually has (auth, chat, upload) - red-team
simulation, per-chunk RAG trust tracking, and the HITL approval queue were
not carried forward; see that archive directory to resurrect any of them.
