"""Evaluates detection.yaml's `routing` and `floor` rules against a live
evidence dict. Deliberately NOT a generic expression language (no eval())
- a structured field/op/value comparator only, so a YAML file can never
become a code-injection surface in a security product. This is the
deterministic layer CLAUDE.md section 8 allows ("hardcoded deterministic
controls are allowed only for security boundaries and infrastructure
safety") - routing/floor decisions are dispatch and hard minimums, never
the ALLOW/MITIGATE/BLOCK judgment itself, which stays the LLM's job.

Also loads detection.yaml's `patterns` section - the regex text a skill's
own evidence signals are computed from. These used to live as hardcoded
Python constants in security_gateway/gateway.py, disconnected from the
skill file that documents them; now the skill file IS the source, and
gateway.py just asks for "whatever patterns any skill declared for this
evidence field" via flat_patterns_for()/nested_patterns_for() below.
Editing a skill's detection.yaml (e.g. adding a new phone-number format)
takes effect with no Python change.
"""
import re

from security_gateway import skills as skills_mod

_ACTION_RANK = {"ALLOW": 0, "MITIGATE": 1, "BLOCK": 2}


def _eval_leaf(cond: dict, evidence: dict) -> bool:
    field = cond["field"]
    op = cond["op"]
    value = cond["value"]
    if field not in evidence:
        return False  # missing evidence never matches - safe default, never a false trigger
    actual = evidence[field]

    if op == "eq":
        return actual == value
    if op == "neq":
        return actual != value
    if op == "gte":
        return actual is not None and actual >= value
    if op == "lte":
        return actual is not None and actual <= value
    if op == "in":
        return actual in value
    raise ValueError(f"Unknown detection.yaml operator '{op}'")


def eval_condition(cond: dict, evidence: dict) -> bool:
    """A condition is a field/op/value leaf, optionally with a nested `and`
    key (another condition dict) that must ALSO be true."""
    if not _eval_leaf(cond, evidence):
        return False
    nested = cond.get("and")
    if nested is not None:
        return eval_condition(nested, evidence)
    return True


def _floor_rules(detection: dict) -> list:
    floor = detection.get("floor")
    if floor is None:
        return []
    return floor if isinstance(floor, list) else [floor]


def apply_floor(category: str, skill_id: str, evidence: dict) -> tuple:
    """Returns (minimum_action_or_None, reason_or_None) - the most
    restrictive matching floor rule for this skill, or (None, None) if no
    floor is defined or none match."""
    skill = skills_mod.load_skill(category, skill_id)
    best_action, best_reason = None, None
    for rule in _floor_rules(skill["detection"]):
        if eval_condition(rule, evidence):
            action = rule["minimum_action"]
            if best_action is None or _ACTION_RANK[action] > _ACTION_RANK[best_action]:
                best_action, best_reason = action, rule.get("reason", "")
    return best_action, best_reason


def enforce_floor(proposed_action: str, floor_action: str) -> str:
    """The floor is a MINIMUM - the proposed action is only ever raised to
    meet it, never lowered."""
    if floor_action is None:
        return proposed_action
    if _ACTION_RANK[floor_action] > _ACTION_RANK[proposed_action]:
        return floor_action
    return proposed_action


def _ceiling_rules(detection: dict) -> list:
    ceiling = detection.get("ceiling")
    if ceiling is None:
        return []
    return ceiling if isinstance(ceiling, list) else [ceiling]


def apply_ceiling(category: str, skill_id: str, evidence: dict) -> tuple:
    """Returns (maximum_action_or_None, reason_or_None) - the MOST
    restrictive matching ceiling rule for this skill (lowest rank), or
    (None, None) if no ceiling is defined or none match.

    A ceiling exists for the opposite failure mode a floor guards against:
    a floor stops the model from talking a genuine minimum DOWN; a
    ceiling stops the model's own excess caution from talking an
    UNRELATED question UP past what the evidence actually supports. Real,
    observed need (2026-08-24): skills/rag/pii-exposure's own floor
    already correctly excludes "PII merely present, question doesn't ask
    for it" from forcing BLOCK - but nothing stopped the model's own free
    judgment from choosing BLOCK anyway just because PII was nearby, on
    both providers this project supports, even after the skill's own
    SKILL.md was reworded to discourage exactly that. gateway.py's
    enforce_ceiling() never lets a ceiling cap below what an INDEPENDENT
    floor already demands - see its call site for why."""
    skill = skills_mod.load_skill(category, skill_id)
    best_action, best_reason = None, None
    for rule in _ceiling_rules(skill["detection"]):
        if eval_condition(rule, evidence):
            action = rule["maximum_action"]
            if best_action is None or _ACTION_RANK[action] < _ACTION_RANK[best_action]:
                best_action, best_reason = action, rule.get("reason", "")
    return best_action, best_reason


def enforce_ceiling(proposed_action: str, ceiling_action: str) -> str:
    """The ceiling is a MAXIMUM - the proposed action is only ever lowered
    to meet it, never raised. Caller (gateway.py) is responsible for never
    letting this drop the action below an independent floor's own
    minimum."""
    if ceiling_action is None:
        return proposed_action
    if _ACTION_RANK[ceiling_action] < _ACTION_RANK[proposed_action]:
        return ceiling_action
    return proposed_action


def route_single(category: str, evidence: dict) -> str:
    """For categories with exactly one skill active per request
    (authentication, files): checks each non-default skill's `routing`
    rules in CATEGORY_SKILLS order, returns the first match, else the
    skill marked `default: true`."""
    default_skill = None
    for skill_id in skills_mod.list_skills(category):
        skill = skills_mod.load_skill(category, skill_id)
        detection = skill["detection"]
        if detection.get("default"):
            default_skill = skill_id
            continue
        for rule in detection.get("routing", []):
            if eval_condition(rule, evidence):
                return skill_id
    if default_skill is None:
        raise ValueError(f"Category '{category}' has no skill marked default: true")
    return default_skill


def route_multi(category: str, evidence: dict) -> list:
    """For categories where more than one skill can be relevant to the
    same request at once (llm, rag - a single chat message can implicate
    both): the `default: true` skill is ALWAYS included as the baseline
    check (e.g. prompt-injection/rag-poisoning run on every message),
    plus every non-default skill whose `routing` rule also matches -
    escalation, not replacement (e.g. jailbreak language ADDS the
    jailbreak skill alongside prompt-injection's baseline, it doesn't
    substitute for it). Always returns at least one skill_id."""
    selected = []
    default_skill = None
    for skill_id in skills_mod.list_skills(category):
        skill = skills_mod.load_skill(category, skill_id)
        detection = skill["detection"]
        if detection.get("default"):
            default_skill = skill_id
            continue
        rules = detection.get("routing", [])
        if rules and any(eval_condition(r, evidence) for r in rules):
            selected.append(skill_id)
    if default_skill is None:
        raise ValueError(f"Category '{category}' has no skill marked default: true")
    selected.append(default_skill)
    return selected


# --- skill-owned regex patterns -------------------------------------------
# Compiled once per field name and cached - skill content is loaded once
# per process already (security_gateway/skills.py's own _CACHE), so this
# just avoids recompiling the same regex list on every request.

_PATTERN_CACHE = {}


def _all_detections():
    for category, skill_ids in skills_mod.CATEGORY_SKILLS.items():
        for skill_id in skill_ids:
            yield skills_mod.load_skill(category, skill_id)["detection"]


def flat_patterns_for(field_name: str) -> list:
    """Every regex string declared under any skill's `patterns.<field_name>`
    (a plain list in that skill's detection.yaml), compiled and merged.
    Case-insensitive by default; a pattern needing exact case (e.g. the
    all-caps jailbreak alias "DAN", to avoid matching the common name
    "Dan") can locally disable it with an inline scoped flag:
    `\\b(?-i:DAN)\\b`."""
    if field_name in _PATTERN_CACHE.get("flat", {}):
        return _PATTERN_CACHE["flat"][field_name]
    compiled = []
    for detection in _all_detections():
        raw = detection.get("patterns", {}).get(field_name)
        if isinstance(raw, list):
            compiled.extend(re.compile(p, re.I) for p in raw)
    _PATTERN_CACHE.setdefault("flat", {})[field_name] = compiled
    return compiled


def nested_patterns_for(field_name: str) -> dict:
    """Same as flat_patterns_for, but for a `patterns.<field_name>` that's a
    mapping of subtype -> pattern list (e.g. pii-exposure's `phone`/`email`
    breakdown) rather than a flat list."""
    if field_name in _PATTERN_CACHE.get("nested", {}):
        return _PATTERN_CACHE["nested"][field_name]
    merged = {}
    for detection in _all_detections():
        raw = detection.get("patterns", {}).get(field_name)
        if isinstance(raw, dict):
            for subtype, pats in raw.items():
                merged.setdefault(subtype, []).extend(re.compile(p, re.I) for p in pats)
    _PATTERN_CACHE.setdefault("nested", {})[field_name] = merged
    return merged
