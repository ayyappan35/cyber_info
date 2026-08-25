"""Loads skills/rag/rag-poisoning/tests/fixtures.yaml and asserts it
against the real threat_router.route_chat/detection code."""
import os

import yaml

from security_gateway import detection, threat_router

_FIXTURES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "skills", "rag", "rag-poisoning", "tests", "fixtures.yaml",
)


def _load_fixtures():
    with open(_FIXTURES_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_rag_poisoning_fixtures():
    for case in _load_fixtures():
        evidence = case["evidence"]
        selected = threat_router.route_chat(evidence)
        by_category = {}
        for cat, sid in selected:
            by_category.setdefault(cat, []).append(sid)

        expected = case["expected_categories_selected"]
        assert sorted(by_category.get("llm", [])) == sorted(expected["llm"]), case["name"]
        assert sorted(by_category.get("rag", [])) == sorted(expected["rag"]), case["name"]

        # Most restrictive floor across every selected skill, mirroring
        # gateway.py's own floor-aggregation logic.
        rank = {"ALLOW": 0, "MITIGATE": 1, "BLOCK": 2, None: -1}
        best = None
        for cat, sid in selected:
            action, _reason = detection.apply_floor(cat, sid, evidence)
            if action is not None and (best is None or rank[action] > rank[best]):
                best = action
        assert best == case["expected_floor_action"], case["name"]
