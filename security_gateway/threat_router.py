"""Threat Router: dispatches an incoming request's evidence to the
specific skill(s) within its category that apply, per detection.yaml's
routing rules (security_gateway/detection.py does the actual evaluation).

- authentication, files: exactly one skill per request (route_single).
- chat (llm + rag together): one message can implicate more than one
  skill at once (e.g. jailbreak language AND a poisoned retrieved
  document) - route_chat returns every skill that matched, always
  including at least the two categories' default skills as a baseline.
"""
from security_gateway import detection


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
