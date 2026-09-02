"""Structured output contract for the Security LLM Discussion node.
Validated with Pydantic - the LLM's raw JSON response is parsed against
this model and rejected (triggering the fail-closed path in gateway.py)
if it doesn't conform, never coerced into "close enough". Same principle
CLAUDE.md section 4.8/4.9 and the earlier RAG-defence work
(agents/rag_security_models.ThreatAssessment, now archived) applied.
"""
from typing import List, Literal

from pydantic import BaseModel, Field

Action = Literal["ALLOW", "MITIGATE", "BLOCK"]


class SecurityDecision(BaseModel):
    action: Action
    confidence: float = Field(ge=0.0, le=1.0)
    threat_indicators: List[str] = Field(default_factory=list)
    reasoning: str = Field(min_length=1)
    # Tool NAMES only, proposed from the tool list the prompt gave the
    # model - arguments are never LLM-sourced (security_gateway/
    # mcp_gateway.py::_args_for builds them deterministically from
    # already-known evidence/identity). Validated against the category's
    # actual catalog in gateway.py, not here - an invalid/hallucinated
    # name is dropped there rather than failing the whole decision.
    required_tools: List[str] = Field(default_factory=list)
    # Which of the skills given in this prompt actually explain this
    # verdict - the Supervisor Agent's "Select/Add Relevant Skills"
    # behavior, reported by the model AFTER reasoning rather than
    # pre-filtered before it. gateway.py feeds EVERY skill in the
    # request's taxonomy scope into the prompt unconditionally regardless
    # of this field (security_gateway/supervisor_agent.py::all_skills_for());
    # this only narrows what gets RECORDED as relevant (skill_ids, the
    # skill used for policy.py's per-skill response.yaml override lookup)
    # - it never narrows what gets REASONED about or ENFORCED. Floor/
    # ceiling in gateway.py still evaluate every offered skill
    # unconditionally, regardless of what's reported here (CLAUDE.md
    # section 8 - the LLM can shape what's recorded, never what's
    # enforced). Validated against the actual skill_ids offered in
    # gateway.py, not here - a hallucinated name is dropped there rather
    # than failing the whole decision, same as required_tools.
    matched_skill_ids: List[str] = Field(default_factory=list)
