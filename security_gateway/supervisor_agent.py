"""Supervisor Agent: the gateway's entry-point orchestrator.
gateway.py::analyze() asks it for the FULL set of taxonomy skill(s) a
given request_category is responsible for (`all_skills_for()`), then
builds ONE Security LLM prompt from three things - Skills (every one of
those skills' SKILL.md content), Knowledge (grounding retrieved from the
threat-knowledge base), and Security Context (the evidence already
gathered for this request):

    Gateway -> Supervisor Agent -> {Skills, Knowledge, Security Context}
            -> Security LLM -> Decision -> Enforcement

This module does NOT filter which skills are relevant - no regex/
condition matching, no hardcoded per-category default, no if/elif of any
kind, and no LLM call of its own. `all_skills_for()` is a pure
enumeration: every skill registered under this request_category's
taxonomy scope, every time. Deciding which of them actually apply to
THIS request is entirely the Security LLM's job
(llm_discussion.py::discuss(), reported back as `matched_skill_ids`) -
the only reasoning step in this pipeline.

The deterministic regex router this module used to also expose
(`route_authentication`/`route_files`/`route_chat`/`route_agents`,
wrapping detection.py's `route_single`/`route_multi`) has been removed
entirely, not just disconnected - it was genuinely dead code (nothing
in the live gateway.py pipeline called it once selection became the
Security LLM's job), and CLAUDE.md/this project's own convention is to
delete confirmed-unused code rather than leave it as an unused fallback.
`detection.py::route_single`/`route_multi` were removed in the same
change for the same reason - they had no other caller.
"""
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
