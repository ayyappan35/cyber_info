"""Supervisor Agent: the gateway's entry-point orchestrator.
gateway.py::analyze() asks it for the FULL set of taxonomy skill(s) a
given request_category is responsible for (`all_skills_for()`), then
builds ONE Security LLM prompt from three things - Skills (every one of
those skills' SKILL.md content), Knowledge (grounding retrieved from the
threat-knowledge base), and Security Context (the evidence already
gathered for this request):

    Gateway -> Supervisor Agent -> {Skills, Knowledge, Security Context}
            -> Security LLM -> Decision -> Policy -> Enforcement

This module does NOT filter which skills are relevant - no regex/
condition matching, no hardcoded per-category default, no LLM call of
its own. `all_skills_for()` is a pure enumeration: every skill registered
under this request_category's taxonomy scope, every time. Deciding which
of them actually apply to THIS request is entirely the Security LLM's
job (llm_discussion.py::discuss()) - the one reasoning step in this
pipeline, per CLAUDE.md section 8's "no hardcoded security decision
logic."

What stays deterministic, and why that's not a contradiction: downstream
of the Security LLM's decision, gateway.py evaluates every one of these
same skills' detection.yaml floor/ceiling UNCONDITIONALLY (not gated by
anything this module decides) before the policy clamp is applied - a
real security boundary the LLM can never bypass (CLAUDE.md section 8
explicitly permits hardcoding THAT, distinct from hardcoding the
decision itself). Since `all_skills_for()` already always returns the
complete scope, that floor/ceiling evaluation was never actually gated
by a selection step to begin with - there is nothing left in this
module for the LLM to "bypass" by omission.

detection.py's `route_single`/`route_multi` (regex dispatch reading each
skill's detection.yaml `routing:` rules) are kept below as
`route_authentication`/`route_files`/`route_chat`/`route_agents` -
still real, still tested - but the live gateway.py pipeline no longer
calls them for skill selection. They're independent, correct utilities
in their own right (and detection.py's `routing:` evaluator is shared
machinery, not duplicated), just disconnected from this module's own
primary path now that selection is the Security LLM's job alone.
"""
from security_gateway import detection
from security_gateway import skills as skills_mod

# request_category (what gateway.py::analyze() is called with) -> the
# taxonomy categories under skills/ it's responsible for. Deliberately
# NOT the full 5-category taxonomy for every request: each
# request_category's evidence dict only carries that scope's fields (e.g.
# a chat request's evidence has no agent-registry fields), so including
# an out-of-scope category's skill would just be unusable noise in the
# Security LLM's prompt - see docs/architecture.md for why full
# cross-category unification is a separate, larger task.
_REQUEST_CATEGORY_TAXONOMY = {
    "authentication": ("authentication",),
    "file_security": ("files",),
    "rag_security": ("llm", "rag"),
    "agent_security": ("agents",),
}


def all_skills_for(request_category: str) -> list:
    """Every (category, skill_id) in request_category's full taxonomy
    scope - unconditional, no filtering. This IS the Supervisor Agent's
    Skills output; gateway.py feeds every one of these skills' SKILL.md
    content into the same Security LLM call, which decides on its own
    which actually apply."""
    if request_category not in _REQUEST_CATEGORY_TAXONOMY:
        raise ValueError(f"Unknown request_category '{request_category}'")
    taxonomy = _REQUEST_CATEGORY_TAXONOMY[request_category]
    return [(category, skill_id) for category in taxonomy for skill_id in skills_mod.list_skills(category)]


# --- deterministic regex router - real, tested, but no longer called by
# gateway.py's live pipeline (see module docstring) ---------------------

def route_authentication(evidence: dict) -> str:
    return detection.route_single("authentication", evidence)


def route_files(evidence: dict) -> str:
    return detection.route_single("files", evidence)


def route_chat(evidence: dict) -> list:
    """Returns a flat list of (category, skill_id) tuples across both the
    llm and rag taxonomy categories."""
    selected = []
    for category in ("llm", "rag"):
        for skill_id in detection.route_multi(category, evidence):
            selected.append((category, skill_id))
    return selected


def route_agents(evidence: dict) -> list:
    """Returns a flat list of (category, skill_id) tuples for an
    agent-to-agent message (request_category="agent_security") -
    skills/agents/tool-abuse (always included, the baseline registered-
    tool-scope check) plus skills/agents/privilege-escalation when its
    routing rule matches. skills/agents/intent-drift has no routing rule
    (see its SKILL.md - genuinely unwired, needs a goal_alignment_score
    this build doesn't compute) so route_multi never selects it."""
    return [("agents", sid) for sid in detection.route_multi("agents", evidence)]
