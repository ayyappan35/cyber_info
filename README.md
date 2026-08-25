# Cyber Defense Assistant — AI Security Gateway

A SOC-analyst chat/RAG web app protected by a single **AI Security
Gateway**: every login, chat question, and document upload is routed
through a Threat Router to a category-specific security skill, reasoned
about by a real LLM (Ollama or Claude, configurable), and enforced by a
deterministic policy layer before anything happens.

```
                         USER / REQUEST
                              |
                              v
                    AI SECURITY GATEWAY (security_gateway/gateway.py)
                              |
                       Threat Router (threat_router.py)
                              |
        +--------------+-------------+--------------+--------------+
        |              |             |              |              |
        v              v             v              v              v
  Authentication      LLM          RAG           Files          Agents
 (login attempts) (chat, direct)(chat, retrieved)(admin uploads)(A2A messages)
        |              |             |              |              |
  skills/authentication/  skills/llm/    skills/rag/     skills/files/   skills/agents/
  credential-stuffing     jailbreak      pii-exposure    archive-bomb    tool-abuse
  account-takeover        model-extraction external-api-abuse malicious-docx privilege-escalation
  brute-force (default)   prompt-injection retrieval-manipulation malicious-pdf (default) intent-drift (unwired)
                                          rag-poisoning (default)
        |              |             |              |              |
        +--------------+-------------+--------------+--------------+
                              |
                              v
                    Security LLM Discussion (llm_discussion.py)
                    -> real Ollama or Claude call, structured/tool-forced output
                              |
                      SECURITY DECISION (decision.py)
                              |
                +-------------+--------------+
                v             v              v
             ALLOW        MITIGATE         BLOCK
                              |
                    (detection.yaml)
                    can only RAISE toward BLOCK or CAP toward ALLOW
                              |
                              v
                MCP Tools (security_gateway/mcp_tools/)
              redis_tool  ·  siem_tool  ·  sandbox_tool
                              |
                        verified (re-read ground truth)
```

A single request can match more than one skill at once (e.g. jailbreak
language in the question *and* a poisoned retrieved document) — the
Threat Router selects every skill that applies, not just one, and the
Security LLM Discussion reasons about all of them together in one call.

## Running it

Pick an LLM provider via `LLM_PROVIDER` in `.env` (copy from
`.env.example`):
- `ollama` (default, local, free) — requires [Ollama](https://ollama.com/)
  running locally with `llama3.2:3b` pulled (`ollama pull llama3.2:3b`).
- `anthropic` — requires `ANTHROPIC_API_KEY` in `.env`.
- `openai` is declared but not implemented for the Security LLM
  Discussion node (raises `NotImplementedError` rather than silently
  falling back to Ollama).

```bash
# one-time: seed knowledge/*.md into the RAG knowledge base
venv/Scripts/python.exe common/seed_knowledge.py
venv/Scripts/python.exe common/seed_threat_knowledge.py   # separate collection the gateway's LLM discussion grounds against

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
  password is correct. The Authentication branch
  (`skills/authentication/{credential-stuffing,account-takeover,
  brute-force}`) reasons about the *pattern* around the attempt
  (failed-attempt count, recent attempt rate, account lock state) and
  can `BLOCK` further attempts from an identity via the Redis/local
  block list, independent of `webapp_db.py`'s own always-on
  `LOCKOUT_THRESHOLD` account lock.
- **Chat** (`POST /api/query`, `.../stream`,
  `backend/routers/query_router.py`): an agentic tool-use loop
  (`backend/pipelines/chat_agent.py`) answers using
  `search_knowledge_base` (internal KB), `get_skill_methodology` (this
  system's own detection methodology), and `search_external_web` (a
  live DuckDuckGo lookup — entity/topic queries only, not full
  questions). Everything the agent actually retrieved, plus the
  question itself, is then checked live by the LLM+RAG Security branch
  (`skills/llm/*` + `skills/rag/*`) — direct prompt injection,
  jailbreak, PII exposure, external-API abuse, and indirect injection
  (a poisoned document trying to hijack the answer) are all in scope.
  Only on `ALLOW`/`MITIGATE` does the agent's answer reach the user;
  `BLOCK` returns the Security LLM Discussion's own real reasoning for
  *why* as the refusal message (not a static canned string), and
  discards the agent's tool-call transcript so flagged content can't
  leak via "Show agent trace" either.
- **Upload** (`POST /api/upload`, admin-only,
  `backend/routers/upload_router.py`): **the File Security gateway
  check is currently disabled**, at the explicit, informed request of
  the project owner (2026-08-25) — every upload is embedded into the
  knowledge base unconditionally, with no scan, no quarantine, no LLM
  review. This was verified working correctly before being turned off
  (a crafted PDF with a real `/OpenAction`→`/JavaScript` payload
  correctly triggered the deterministic floor → `BLOCK` → quarantine →
  verified-never-ingested). To re-enable: route the upload through
  `security_gateway.gateway.analyze("file_security", ...)` again before
  `add_to_kb()`, as `skills/files/malicious-pdf/SKILL.md` and
  `backend/pipelines/ingest_chroma.py`'s docstring describe — see git
  history for `upload_router.py`'s prior version.

## Deterministic vs. LLM judgment

`policies/security_gateway_policy.yaml` is the only place that decides
what a proposed action is *allowed* to do (`security_gateway/policy.py`):
which actions are enabled per category, the minimum LLM confidence
required before an action is enforced at full strength (a low-confidence
`BLOCK` is stepped down to `MITIGATE`, never trusted outright), and the
fail-closed action if the Security LLM Discussion node never returns a
schema-valid decision (see `security_gateway/decision.py` -
`SecurityDecision`, Pydantic-validated, never parsed from free text). A
skill's own `response.yaml` can override the category default for that
skill specifically (a stricter confidence floor, a different enforcement
effect). On top of policy, each skill's `detection.yaml` can define a
deterministic **floor** (raises the action to a hard minimum the LLM
can't talk down, e.g. 2+ PDF active-content markers) and **ceiling**
(caps the action so the LLM's own excess caution can't over-block an
unrelated question). The LLM reasons over evidence; it can never edit
policy or bypass these deterministic boundaries.

## MCP Tools

- **`redis_tool.py`** — real `redis.Redis.from_url(...)` when `REDIS_URL`
  is set and the `redis` package is installed; otherwise a working
  SQLite-backed fallback (`common/security_db.py`) with identical
  block/expiry semantics — never a stub. `backend()` reports which is
  active.
- **`siem_tool.py`** — thin wrapper over `common/security_db.py`'s
  `security_events`/`gateway_decisions` tables: a real, queryable,
  persistent security-event log.
- **`sandbox_tool.py`** — real local quarantine storage
  (`sandbox/` on disk for file bytes, `security_db.sandbox_items` for
  metadata/text evidence). Nothing sandboxed is ever embedded or made
  retrievable. (Currently only reached via the chat path's
  `BLOCK`/`MITIGATE` — file uploads don't route through the gateway at
  all right now; see the Upload note above.)

All three are visible in the Admin Dashboard's **Overview** tab
(`GET /api/security/decisions`, `/sandbox`, `/blocked`, `/events`).

## MCP Tool Authorization Gateway and attack chains

The Security LLM Discussion node may also propose specific remediation
tools (`required_tools` in its structured decision) - `security_gateway/
mcp_gateway.py` independently authorizes each one before it runs: tool
must be in the 13-tool catalog, must be scoped to the request's category,
must not be rate-limited, and `risk: critical` tools (`block_ip`,
`terminate_session`, `remove_vector`) queue for admin approval
(`GET/POST /api/security/tool-calls*`) rather than auto-executing.
`search_external_web` is in the same catalog but isn't LLM-proposed like
the others - the chat agent calls it directly mid-conversation, routed
through `authorize_and_execute()` purely for its rate limit, SIEM log,
and pre-call SSRF guard (a query naming a private/internal host is
refused before the request leaves the network). See `docs/architecture.md`
for the full tool catalog and honesty notes on
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
common/                  Shared app infrastructure
  config.py                Settings (env-driven: LLM provider, DB paths, CORS, ...)
  security_db.py           SIEM event log, gateway decision log, block list, sandbox store
  logging_config.py        structured logging + secret redaction
  observability.py         optional MLflow/LangSmith tracing
  seed_knowledge.py        Ingest knowledge/*.md into the RAG knowledge base
  seed_threat_knowledge.py Ingest knowledge/cyber_defence/*.md into the separate threat-knowledge collection
backend/                 FastAPI app: routers, auth, webapp DB, RAG pipelines
  routers/                auth · conversations · query · upload · admin · security · agent
  pipelines/               rag_search.py · rag_graph_chroma.py · chat_agent.py · ingest_chroma.py · threat_knowledge.py
security_gateway/         The AI Security Gateway
  gateway.py               orchestrates: route -> skill -> LLM discussion -> policy/floor/ceiling -> MCP tools -> verify
  threat_router.py         category -> skill(s) dispatch (route_single / route_multi)
  detection.py              deterministic routing/floor/ceiling rule evaluator + skill-owned regex patterns
  llm_discussion.py         real Ollama or Claude call, structured/tool-forced output, retried + validated
  decision.py               SecurityDecision Pydantic schema
  policy.py                  loads/enforces policies/security_gateway_policy.yaml
  skills.py                  loads skills/<category>/<skill-id>/SKILL.md + detection.yaml + response.yaml
  mcp_gateway.py             13-tool catalog: authorization, rate limits, approval queue
  agent_registry.py, chain_detection.py, archive_scan.py, runtime_config.py
  mcp_tools/                redis_tool.py · siem_tool.py · sandbox_tool.py
skills/                   "how to investigate" methodology, per category
  authentication/           credential-stuffing · account-takeover · brute-force (default)
  llm/                      jailbreak · model-extraction · prompt-injection (default)
  rag/                      pii-exposure · external-api-abuse · retrieval-manipulation · rag-poisoning (default)
  files/                    archive-bomb · malicious-docx · malicious-pdf (default)
  agents/                   tool-abuse · privilege-escalation · intent-drift (not wired - see its SKILL.md)
policies/                 security_gateway_policy.yaml - "what's permitted"
knowledge/                Markdown runbooks (business KB) + cyber_defence/ (threat-knowledge grounding)
frontend/                 React + Vite + Tailwind SPA
tests/                    231 tests mirroring security_gateway/ + backend/
docs/                     architecture.md
sandbox/                  Quarantined file bytes on disk (gitignored)
cyberdefense.db           Shared SQLite file (security_db.py's tables + backend/webapp_db.py's tables, gitignored)
kb_chroma_db/             Chroma vector store (gitignored, regenerated by seeding)
```

## Recent changes (2026-08-25)

This platform was previously a multi-agent LangGraph orchestrator (a
red/blue/governance cyber-range simulation plus per-domain defense agents
- RAG defence, rogue-agent detection, A2A security, etc.), replaced
end-to-end with the single AI Security Gateway pipeline above at the
user's explicit request. Since then:
- Shared app infrastructure (`config.py`, `security_db.py`,
  `logging_config.py`, `observability.py`, the seed scripts) moved from
  the project root into `common/`.
- The skills taxonomy grew from 3 flat skills (`brute_force`,
  `rag_poisoning`, `malicious_pdf`) to the 5-category, ~15-skill
  structure under `skills/` shown above, each routed independently by
  `threat_router.py`.
- The chat agent gained a third tool, `search_external_web` (live
  DuckDuckGo lookup), alongside the two internal-knowledge tools.
- The File Security gateway check on uploads was explicitly disabled
  (see the Upload note above) - a deliberate, informed change, not an
  oversight.
- The prior multi-agent architecture's code, previously preserved under
  `_archive_2026-08-24_pre_gateway_rebuild/`, has since been deleted.
