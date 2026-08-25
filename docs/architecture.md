# Architecture

See `README.md` for the request-flow diagram and the three request paths
(login, chat, upload). This document covers what README doesn't: honest
scope limits and the rebuild rationale.

## Why this exists

The platform was rebuilt on 2026-08-24 around a specific architecture
diagram the user provided: a single AI Security Gateway with a Threat
Router dispatching to three category branches (Authentication / RAG
Security / File Security), each backed by one skill, converging on one
Security LLM Discussion node, enforced by a deterministic policy layer,
executed through three MCP tools (Redis / SIEM / Sandbox), and verified.
The prior architecture (a multi-agent LangGraph orchestrator - red/blue/
governance cyber-range simulation, per-domain defense agents for RAG/
memory/agent-to-agent/rogue-agent detection, a 10-skill registry, 4
policy files, per-chunk RAG trust tracking) was archived, not deleted,
under `_archive_2026-08-24_pre_gateway_rebuild/` at the project root.

## Honest scope of the current build

**Real and tested** (see `tests/`, 44 tests, and live-verified via direct
API calls at rebuild time - login/chat/upload all exercised against a
running Ollama instance, not mocked):
- The full gateway pipeline for all three categories, including a real
  Ollama LLM call each time (no caching a verdict across requests).
- Deterministic policy clamping (confidence thresholds, enabled/disabled
  actions, fail-closed default) - `security_gateway/policy.py`.
- Real MCP tool side effects: Redis/SQLite-fallback identity blocking,
  SIEM event + decision logging, sandbox quarantine (files written to
  disk under `sandbox/`, never embedded).
- Verification: `gateway.py::_verify()` re-reads ground truth (is the
  identity actually blocked? does the sandbox item actually exist?)
  before reporting an action as enforced.
- Deterministic PDF active-content detection (`/JavaScript`, `/JS`,
  `/OpenAction`, `/AA` byte markers) as one input to the file_security
  LLM discussion, not a standalone rule.

**Deliberately not carried forward from the prior build** (a scope
narrowing to match the new diagram, not an oversight):
- Red-team attack simulation / cyber-range demo (`orchestrator.py`,
  `agents/red_team.py`, `agents/blue_team.py`, `agents/governance.py`) -
  archived. The new diagram has no red-team box.
- Per-chunk RAG trust tracking, embedding-anomaly scoring, staleness
  tracking, context-time canary scanning (all from the prior RAG-defence
  layer) - superseded by the simpler "checked live on every query, and
  again at upload" model the new diagram implies. A document is either
  fully embedded (post-ALLOW) or not embedded at all (MITIGATE/BLOCK
  sandboxes the whole file); there is no per-chunk granularity.
- The HITL admin-approval queue (`pending_approvals`) - the new diagram
  shows deterministic ALLOW/MITIGATE/BLOCK enforcement, not a
  human-approval step. `MITIGATE` (sandbox + admin review via
  `GET/POST /api/security/sandbox*`) is the closest equivalent.
- Agent-to-agent security, rogue-agent detection, memory defence - there
  is only one reasoning node (Security LLM Discussion) in the new
  design, not multiple cooperating agents, so these categories don't
  apply the way they did before.
- MITRE/OWASP attack-scenario taxonomy tracking
  (`attack-scenarios/*/scenarios.yaml`) - archived along with the
  red-team/rogue-agent machinery it was scoring.

## MCP Tool Authorization Gateway and attack-chain detection (2026-08-24)

A second round the same day added two more real, tested mechanisms on
top of the taxonomy above, matching a user-provided design: the Security
LLM Discussion node may now *propose* specific remediation tools as part
of its structured decision, and those proposals are independently
authorized before anything executes.

- **`security_gateway/mcp_gateway.py`** - a 9-tool catalog
  (`get_login_attempts`, `get_ip_reputation`, `rate_limit_user`,
  `require_mfa`, `block_ip`, `terminate_session`, `get_document_provenance`,
  `quarantine_document`, `remove_vector`), each with real risk/
  category-scope/rate-limit/requires_approval metadata. The LLM proposes
  tool NAMES only (`decision.py`'s `required_tools: List[str]`) -
  arguments are always filled in deterministically from already-known
  identity/evidence, never parsed from the model's own text (a
  correctness AND a small-model-reliability decision - see that module's
  docstring). Category scoping is a real security boundary: an
  authentication skill's proposal of a files/rag tool is rejected
  regardless of what the model output. `risk: critical` tools
  (`block_ip`, `terminate_session`, `remove_vector`) queue in
  `security_db.pending_tool_calls` for admin approval
  (`GET/POST /api/security/tool-calls*`) rather than auto-executing.
- **`require_mfa`/`terminate_session`** are honestly scoped down from
  their names' full implication: this build has no real second-factor
  challenge flow, so `require_mfa` sets an admin-clearable access hold
  (`webapp_db.app_users.mfa_hold`); `terminate_session` sets a
  `sessions_invalidated_before` cutoff checked by `auth.get_current_user`
  against each JWT's `iat` claim - a real "log out everywhere" mechanism
  for stateless JWTs, not a session-store lookup this app doesn't have.
- **`get_ip_reputation`** is internal-history-only (count of this
  system's own prior `block_ip` calls against a source) - never a
  fabricated external threat-intel feed, which this project has no real
  data source for.
- **`security_gateway/chain_detection.py`** - flags when one identity
  triggers 2+ DISTINCT non-ALLOW skills (across one or more categories)
  within a 30-minute window, e.g. a `malicious-docx` upload followed by a
  `jailbreak` chat attempt from the same account. Purely a query over
  already-logged `gateway_decisions` history - detects the SHAPE only
  (multiple distinct skills, one identity), never asserts what kind of
  attack it is. Live-verified: a real macro-bearing `.docx` upload
  followed by a real jailbreak chat message from one account correctly
  produced `{"chained": true, "skill_ids": ["jailbreak", "malicious-docx",
  "prompt-injection", "rag-poisoning"]}` and a logged
  `ATTACK_CHAIN_DETECTED` SIEM event.

### Explicitly NOT built this round (documented roadmap, not started)

Per explicit user scoping - building either of these as a stub would
have violated CLAUDE.md's no-fake-implementations rule, so neither was
attempted even partially:

- **Skill registry versioning** (version/hash/confidence/false-positive
  tracking per skill, rollback). The taxonomy's `detection.yaml`/
  `response.yaml`/`SKILL.md` files exist and are real, but there is no
  registry database tracking their version history or empirical
  accuracy over time.
- **Autonomous skill-generation pipeline** (new-incident-triggered
  candidate `SKILL.md` drafting by an LLM, adversarial test generation,
  sandboxed validation, canary rollout, human review gate before
  promotion to the registry). A real version of this is a substantial
  project in its own right - candidate generation, automated adversarial
  testing, and canary metrics/rollback all need real design work, not a
  thin wrapper. Not started.

## Known limitations (observed, not hypothetical)

- `llama3.2:3b` occasionally produces prose in `reasoning` that
  overstates the evidence (e.g. calling a `.md` file's active-content
  scan a "PDF" scan, or naming a marker that wasn't actually present) -
  observed during live rebuild testing. The *enforcement* (which action
  is taken) is correct either way because it's driven by the structured
  `action`/`confidence` fields, validated by `security_gateway/decision.py`,
  not by parsing the prose - but the reasoning text shown in the Admin
  Dashboard should be read as the model's rationale, not as a verified
  fact list.
- `redis_tool.py`'s in-process attempt-count tracking (`_attempts`, a
  `defaultdict(deque)`) is correct for this app's single-uvicorn-worker
  deployment but would need a shared backend (real Redis, always) to
  stay correct across multiple worker processes - documented in that
  module's docstring, not silently assumed away.
- No automated adversarial-embedding-evasion testing, no PostgreSQL
  migration, no real multi-tenancy - none of these were ever built in
  this project and remain out of scope here too.
