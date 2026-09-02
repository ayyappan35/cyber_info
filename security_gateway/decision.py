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


class ToolCall(BaseModel):
    """One LLM-proposed tool invocation - name AND arguments, both supplied
    directly by the Security LLM (2026-09-02: mcp_gateway.py's former
    deterministic `_args_for()` per-tool-name argument builder was removed
    entirely - see mcp_gateway.py's module docstring for the risk this
    documents: a prompt-injected message can now steer arguments like
    source_ip/username/document_id at an arbitrary attacker-chosen target,
    not just the current request's own trusted evidence, the same way
    `required_tools` naming the tool itself already could). `name` is
    validated against the tool catalog offered for this category in
    gateway.py, same as before; `arguments` are passed through to the
    tool's real executor as-is - a missing/malformed key is caught there
    (mcp_gateway.authorize_and_execute() denies the call rather than
    crashing), never sanitized or re-derived here."""
    name: str
    arguments: dict = Field(default_factory=dict)


class SecurityDecision(BaseModel):
    action: Action
    confidence: float = Field(ge=0.0, le=1.0)
    threat_indicators: List[str] = Field(default_factory=list)
    reasoning: str = Field(min_length=1)
    # Tool name + arguments, both LLM-supplied (see ToolCall above).
    # `name` is validated against the category's actual catalog in
    # gateway.py, not here - an invalid/hallucinated name is dropped there
    # rather than failing the whole decision.
    required_tools: List[ToolCall] = Field(default_factory=list)
    # Which of the skills given in this prompt actually explain this
    # verdict - the Supervisor Agent's "Select/Add Relevant Skills"
    # behavior, reported by the model AFTER reasoning rather than
    # pre-filtered before it. gateway.py feeds EVERY skill in the
    # request's taxonomy scope into the prompt unconditionally regardless
    # of this field (security_gateway/supervisor_agent.py::all_skills_for());
    # this only narrows what gets RECORDED as relevant (skill_ids, the
    # skill used for policy.py's per-skill response.yaml override lookup)
    # - it never narrows what gets REASONED about (every offered skill's
    # content is still in the prompt). agentic_system branch: detection.py's
    # floor/ceiling are no longer called from gateway.py at all - this
    # field only affects the audit trail (skill_ids, the per-skill
    # policy.py response.yaml lookup), not any remaining deterministic
    # enforcement, because there isn't any left to bypass or not-bypass
    # (see docs/AGENTIC_SYSTEM_EXPERIMENT.md). Validated against the
    # actual skill_ids offered in gateway.py, not here - a hallucinated
    # name is dropped there rather than failing the whole decision, same
    # as required_tools.
    matched_skill_ids: List[str] = Field(default_factory=list)
