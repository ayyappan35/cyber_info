---
skill_id: intent-drift
name: Agent Intent Drift Detection
category: agents
version: 1.0.0
owner_agent: unwired
implementation: none - see "current status" below
---

# Current status: not wired to any live enforcement path

Same status as the other `agents/*` skills - a real specification, not
connected to any code path. See `agents/tool-abuse/SKILL.md` for why.

# What security task is being performed (if wired)

Detecting an autonomous agent's sequence of actions drifting away from
its originally stated task/goal over a multi-step session - e.g. an
agent tasked with "summarize this incident" that starts, several turns
later, requesting unrelated data exports. Distinct from `tool-abuse`
(one out-of-scope tool call) and `privilege-escalation` (role change) -
this is about the *trajectory* of a session, not a single event.

# How the agent should investigate

Would compare each turn's chosen action against the session's original
stated goal (semantic similarity or explicit goal-tracking), flagging a
sustained divergence rather than a single odd turn (one unusual action
is often legitimate exploration; a consistent trajectory away from the
stated goal is the real signal).

# What evidence should be collected

`detection.yaml`'s `signals`: `session_id`, `original_goal_summary`,
`turn_count`, `actions_this_session` (list), `goal_alignment_score`
(would require a real scoring mechanism - not something this build has
implemented; see "what security boundaries apply").

# What security boundaries apply (if wired)

This is the hardest of the three `agents/*` skills to make genuinely
deterministic - "drift" is inherently a judgment call, not a clean
threshold like `tool-abuse`/`privilege-escalation`. Would need real design
work on what `goal_alignment_score` even means and how it's computed
(embedding similarity between goal and action descriptions is one
option, explicitly flagged here as unimplemented, not glossed over) before
this could be more than an LLM free-reasoning check with no deterministic
floor at all.

# How the result should be verified (if wired)

Would follow this project's standard pattern (sandbox evidence, re-read
before reporting enforced) but has no obvious single corrective MCP
action the way `tool-abuse`/`privilege-escalation` do (isolate the agent?
pause the session? both would need building).
