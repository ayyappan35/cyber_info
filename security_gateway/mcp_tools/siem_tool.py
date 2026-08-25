"""SIEM MCP tool: thin, explicit wrapper over security_db.py's
security_events and gateway_decisions tables. Kept as its own module
(rather than callers using security_db directly) so the gateway's call
sites read as "call the SIEM tool", matching the architecture diagram's
MCP Tools box, and so this is the one place that would change if a real
external SIEM (Splunk/Elastic) ever replaced the local SQLite log.
"""
from common import security_db

security_db.init_db()


def log_event(agent_id: str, tool_name: str, decision: str, risk: str = "", detail: str = "") -> None:
    security_db.log_security_event(agent_id=agent_id, tool_name=tool_name, decision=decision,
                                    risk=risk, detail=detail)


def log_decision(category: str, identity: str, action: str, raw_action: str, confidence: float,
                  threat_indicators: list, reasoning: str, enforced: bool, sandbox_id: str = None,
                  skill_ids: list = None) -> int:
    return security_db.log_gateway_decision(
        category=category, identity=identity, action=action, raw_action=raw_action,
        confidence=confidence, threat_indicators=threat_indicators, reasoning=reasoning,
        enforced=enforced, sandbox_id=sandbox_id, skill_ids=skill_ids,
    )


def recent_events(limit: int = 50) -> list:
    return security_db.list_security_events(limit=limit)


def recent_decisions(limit: int = 50, category: str = None) -> list:
    return security_db.list_gateway_decisions(limit=limit, category=category)
