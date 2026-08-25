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
