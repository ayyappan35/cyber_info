---
skill_id: pii-exposure
name: PII / Sensitive Data Exposure Prevention
category: rag
version: 1.0.0
owner_agent: security_gateway.chat_security
implementation: security_gateway/gateway.py, security_gateway/detection.py
---

# What security task is being performed

Distinct from `rag-poisoning` (retrieved content trying to hijack the
model) and `prompt-injection`/`jailbreak` (the question trying to
override behavior) - this skill catches retrieved content that contains
real personal data (phone numbers, email addresses) about to be handed
to whoever asked, regardless of whether the question or the document
itself is "malicious" in any conventional sense. A resume uploaded in
good faith, containing a real phone number and email, is not an attack -
but surfacing that data to any authenticated user who asks is a data
governance failure this system had, until this skill closed it.

# How the agent should investigate

The Threat Router adds this skill whenever `context_contains_pii` is
true (deterministic regex evidence over the retrieved context, computed
in `gateway.py::gather_chat_evidence` - phone number and email patterns
today; see "what security boundaries apply" for what's NOT covered yet).
Routing is deliberately broad (PII presence alone), so this skill's
guidance reaches the discussion far more often than it should actually
change the verdict - the real question to weigh is narrow:

**Does THIS question ask for the phone number/email itself (or an
equivalent way of reaching the person), not merely "does the retrieved
chunk happen to contain one somewhere"?** `question_requests_personal_info`
is that exact check, already computed. If the retrieved chunk contains
PII but the question is asking about something else entirely in the same
document (skills, work history, a project, a summary) - answer it
normally using the rest of the content; simply don't proactively surface
the phone/email/contact fields themselves. Merely being IN a chunk that
also contains PII is not, on its own, ANY reason to withhold an unrelated
answer - PII presence gets this skill into the discussion, it does not
by itself make disclosure the topic under discussion.

Unlike every other `rag/llm` skill, this one's floor is not advisory -
`detection.yaml`'s `floor` forces `BLOCK` unconditionally once both
`context_contains_pii` AND `question_requests_personal_info` are true,
regardless of what the model concludes (deliberate privacy-by-default
policy). But the floor is only ever a MINIMUM, never a ceiling - it
cannot correct a model that blocks an unrelated question on its own
initiative just because PII happens to be nearby. That correction has to
come from the reasoning above: when `question_requests_personal_info` is
false, there is no policy basis for withholding anything, and the
discussion should say so plainly rather than treating PII-adjacency
itself as inherently risky.

# What evidence should be collected

`context_contains_pii`, `pii_types_found` (e.g. `["phone", "email"]`) -
`gateway.py::gather_chat_evidence`'s `_PII_PATTERNS`.
`search_threat_knowledge("sensitive data exposure PII disclosure")`.

# What security boundaries apply

- `detection.yaml`'s `floor`: requires BOTH `context_contains_pii ==
  true` AND `question_requests_personal_info == true` before forcing
  **BLOCK** unconditionally. This two-condition requirement is itself a
  fix for a real, observed false positive (2026-08-24): gating on PII
  presence alone blocked EVERY question that happened to retrieve a
  chunk containing a phone/email anywhere in it - "what's his top skill
  set" was blocked exactly as hard as "what's his phone number", because
  both retrieved the same resume chunk. Routing (which skills join the
  discussion) still stays broad on PII presence alone; only the hard
  floor was narrowed.
- `detection.yaml`'s `ceiling`: the same fix's second half, added the
  same day once the floor above turned out not to be enough on its own -
  the model kept choosing BLOCK by its own free judgment for exactly the
  cases the floor excludes (`question_requests_personal_info == false`),
  on both providers, even after this file explicitly told it not to.
  Caps the action at **MITIGATE** whenever that condition holds,
  regardless of what the model proposed - symmetric to the floor, but
  capping excess caution instead of raising insufficient caution. Never
  lets an independent floor from another skill (e.g. real jailbreak
  language present in the same request) get capped below its own
  minimum - see `gateway.py`'s ceiling application for the guard.
- **Not the passive sandbox path** (unlike every other skill's BLOCK):
  `response.yaml` overrides the effect to `tool_approval_required`, which
  `gateway.py` handles by deterministically queuing the
  `disclose_pii_answer` MCP tool (`security_gateway/mcp_gateway.py`) for
  explicit admin approve/deny - the same real authorization gate
  `block_ip`/`terminate_session`/`remove_vector` go through
  (`GET/POST /api/security/tool-calls*`, shown in the Admin Dashboard's
  "Pending Tool Approvals"), not the sandbox tab. Approving it generates
  the real answer AT THAT MOMENT (not before), shown only to the admin -
  nothing currently re-delivers an approved answer automatically back
  into the requester's chat; an admin who approves has to relay it
  manually. Flagged as a real, known gap, not glossed over.
- **Coverage gap, stated honestly**: only phone numbers and email
  addresses are detected today. Physical addresses, government ID
  numbers, dates of birth, and other PII categories are NOT covered by
  this skill's regex patterns yet - a document containing only those
  would not trigger this skill. This is a real, live gap, not a
  hypothetical one.
- This skill only protects retrieval at QUERY time - it does not remove
  already-answered PII from a conversation's history, and it does not by
  itself re-scan/quarantine the source document at rest (that's
  `files/malicious-pdf`'s job, which does not currently check for PII
  either - see `docs/architecture.md` for the honest list of what this
  round did and didn't close).

# How the result should be verified

Not the sandbox re-read pattern the other skills use - instead,
`mcp_gateway.authorize_and_execute("disclose_pii_answer", ...)` re-reads
`security_db.get_pending_tool_call()` to confirm the approval-queue row
actually exists before the BLOCK is reported as enforced; a later
approval re-reads the same row to confirm it's still `pending` before
executing, and stores the generated answer on that row as `result` for
audit.
