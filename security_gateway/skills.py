"""Loads the nested skills/<category>/<skill-id>/ taxonomy - SKILL.md
("how to investigate", never authorization - CLAUDE.md section 6),
detection.yaml (deterministic signals/routing/floor - security_gateway/
detection.py is what actually evaluates it), and an optional response.yaml
(per-skill policy override - security_gateway/policy.py).
"""
import os

import yaml

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(_PROJECT_ROOT, "skills")

# The full taxonomy, in routing-priority order within each category (most
# specific/rare pattern first, `default: true` skill last - detection.py
# checks routing rules in this order and falls back to the default).
CATEGORY_SKILLS = {
    "authentication": ["credential-stuffing", "account-takeover", "brute-force", "password-spraying",
                        "credential-enumeration", "impossible-travel", "new-device", "mfa-fatigue"],
    "llm": ["jailbreak", "model-extraction", "prompt-injection"],
    "rag": ["pii-exposure", "external-api-abuse", "retrieval-manipulation", "rag-poisoning"],
    "files": ["archive-bomb", "malicious-docx", "malicious-pdf"],
    "agents": ["tool-abuse", "privilege-escalation", "intent-drift"],  # not wired - see each SKILL.md
}


def _parse_frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    fm = {}
    for line in text[3:end].strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            fm[key.strip()] = value.strip()
    return fm


def _skill_dir(category: str, skill_id: str) -> str:
    if category not in CATEGORY_SKILLS or skill_id not in CATEGORY_SKILLS[category]:
        raise ValueError(f"No skill '{skill_id}' registered under category '{category}'")
    return os.path.join(SKILLS_DIR, category, skill_id)


def _load_yaml(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


_CACHE = {}


def load_skill(category: str, skill_id: str) -> dict:
    """Returns {"skill_id", "category", "frontmatter", "content" (SKILL.md),
    "detection" (parsed detection.yaml), "response" (parsed response.yaml,
    {} if absent)}."""
    cache_key = (category, skill_id)
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    d = _skill_dir(category, skill_id)
    with open(os.path.join(d, "SKILL.md"), "r", encoding="utf-8") as f:
        text = f.read()

    result = {
        "skill_id": skill_id,
        "category": category,
        "frontmatter": _parse_frontmatter(text),
        "content": text,
        "detection": _load_yaml(os.path.join(d, "detection.yaml")),
        "response": _load_yaml(os.path.join(d, "response.yaml")),
    }
    _CACHE[cache_key] = result
    return result


def list_skills(category: str) -> list:
    if category not in CATEGORY_SKILLS:
        raise ValueError(f"Unknown category '{category}'")
    return list(CATEGORY_SKILLS[category])
