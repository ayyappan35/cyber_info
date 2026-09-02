"""Loads and applies policies/security_gateway_policy.yaml - the
deterministic layer between the LLM's proposed decision and what actually
gets enforced (CLAUDE.md section 7/8). Fail-loud: a malformed policy file
raises at load time rather than silently falling back to something
permissive.
"""
import os

import yaml
from pydantic import BaseModel, ValidationError

from security_gateway import skills as skills_mod

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(_PROJECT_ROOT, "policies", "security_gateway_policy.yaml")

_ACTIONS = ("ALLOW", "MITIGATE", "BLOCK")
_STEP_DOWN = {"BLOCK": "MITIGATE", "MITIGATE": "ALLOW", "ALLOW": "ALLOW"}


class _CategoryPolicy(BaseModel):
    skill: str
    actions: dict
    min_confidence_to_enforce: float


class _Policy(BaseModel):
    categories: dict
    fail_closed_action: dict


_cached: _Policy | None = None


def load_policy() -> _Policy:
    global _cached
    if _cached is not None:
        return _cached
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict) or "categories" not in raw or "fail_closed_action" not in raw:
        raise ValueError(f"{POLICY_PATH} is malformed: missing 'categories' or 'fail_closed_action'")
    for cat, cfg in raw["categories"].items():
        try:
            _CategoryPolicy(**cfg)
        except ValidationError as e:
            raise ValueError(f"{POLICY_PATH}: category '{cat}' is malformed: {e}")
        for action in cfg["actions"]:
            if action not in _ACTIONS:
                raise ValueError(f"{POLICY_PATH}: category '{cat}' has unknown action '{action}'")
    _cached = _Policy(**raw)
    return _cached


def _skill_response(skill: tuple | None) -> dict:
    """skill, if given, is (taxonomy_category, skill_id) e.g.
    ("authentication", "credential-stuffing") - looks up that skill's
    response.yaml (skills.py already loads/caches it)."""
    if skill is None:
        return {}
    taxonomy_category, skill_id = skill
    return skills_mod.load_skill(taxonomy_category, skill_id).get("response") or {}


def _min_confidence(category: str, cat_policy: dict, skill: tuple | None) -> float:
    override = _skill_response(skill).get("min_confidence_to_enforce")
    return override if override is not None else cat_policy["min_confidence_to_enforce"]


def clamp_action(category: str, proposed_action: str, confidence: float, skill: tuple | None = None) -> str:
    """Enforces two deterministic rules the LLM cannot override:
    1. An action disabled for this category in policy is never enforced -
       stepped down to the next-weakest enabled action.
    2. A proposal below the effective min_confidence_to_enforce (the
       skill's own response.yaml override if it has one, else the
       category default) is stepped down one level, regardless of what
       action it named - low-confidence BLOCK becomes MITIGATE,
       low-confidence MITIGATE becomes ALLOW (but is still logged as the
       original proposal for audit purposes by the caller).

    `skill`, if given, is (taxonomy_category, skill_id) - the specific
    skill the Supervisor Agent selected, whose response.yaml may override
    the category-level config below."""
    policy = load_policy()
    cat_policy = policy.categories.get(category)
    if cat_policy is None:
        raise ValueError(f"No policy configured for category '{category}'")

    action = proposed_action
    if action not in _ACTIONS:
        action = "MITIGATE"  # unrecognized action from a malformed decision - never trust it as ALLOW

    action_cfg = cat_policy["actions"].get(action, {})
    if not action_cfg.get("enabled", False):
        action = _STEP_DOWN[action]

    if confidence < _min_confidence(category, cat_policy, skill):
        action = _STEP_DOWN[action]

    return action


def fail_closed_action(category: str) -> str:
    policy = load_policy()
    return policy.fail_closed_action.get(category, "MITIGATE")


def action_effect(category: str, action: str, skill: tuple | None = None) -> str | None:
    override = _skill_response(skill).get("overrides", {}).get(action, {}).get("effect")
    if override is not None:
        return override
    policy = load_policy()
    return policy.categories[category]["actions"].get(action, {}).get("effect")


def action_config_value(category: str, action: str, field: str, skill: tuple | None = None, default=None):
    """Generic per-action config lookup (e.g. block_ttl_seconds) - checks
    the skill's response.yaml override first, falls back to the
    category-level policy, then `default`."""
    override = _skill_response(skill).get("overrides", {}).get(action, {}).get(field)
    if override is not None:
        return override
    policy = load_policy()
    return policy.categories[category]["actions"].get(action, {}).get(field, default)
