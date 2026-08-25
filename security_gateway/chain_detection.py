"""Attack-chain detection: flags when the SAME identity triggers multiple
DIFFERENT taxonomy skills (across one or more categories) within a short
window - e.g. a malicious-pdf upload followed shortly by a jailbreak
attempt in chat from the same account is a much stronger signal together
than either alone. Purely a real, deterministic query over
security_db.gateway_decisions (already-logged history) - no new state to
maintain, no LLM call, no hardcoded "if X then Y" attack-type logic
(CLAUDE.md section 8): it only detects the SHAPE (multiple distinct
non-ALLOW skills, one identity, one window), never asserts what kind of
attack it is - that's still Threat Analysis/human judgment territory,
this module hands them the pattern, not a verdict.
"""
from common import security_db

DEFAULT_WINDOW_SECONDS = 1800  # 30 minutes


def detect_chain(identity: str, window_seconds: int = DEFAULT_WINDOW_SECONDS, limit: int = 200) -> dict:
    """Returns {"chained": bool, "skill_ids": [...], "categories": [...],
    "decision_ids": [...]}` - `chained` is true only when 2+ DISTINCT
    skill_ids, each from a non-ALLOW decision, appear for this identity
    within the window. A single skill firing repeatedly (e.g. brute-force
    alone) is not a chain - it's the same skill's own escalation, already
    handled by that skill's floor/policy."""
    from datetime import datetime, timedelta, timezone

    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat(timespec="seconds")
    recent = [d for d in security_db.list_gateway_decisions_for_identity(identity, cutoff, limit=limit)
              if d["action"] != "ALLOW"]

    distinct_skills = {}
    for d in recent:
        for skill_id in d["skill_ids"]:
            distinct_skills.setdefault(skill_id, []).append(d)

    if len(distinct_skills) < 2:
        return {"chained": False, "skill_ids": [], "categories": [], "decision_ids": []}

    decision_ids = sorted({d["id"] for docs in distinct_skills.values() for d in docs})
    categories = sorted({d["category"] for docs in distinct_skills.values() for d in docs})
    return {
        "chained": True,
        "skill_ids": sorted(distinct_skills.keys()),
        "categories": categories,
        "decision_ids": decision_ids,
    }
