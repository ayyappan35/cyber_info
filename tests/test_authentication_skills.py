"""Loads skills/authentication/brute-force/tests/fixtures.yaml and
skills/authentication/brute-force/examples/example_attack.yaml and
asserts them against the real supervisor_agent/detection code - these
fixture files are not decorative documentation, they are executed."""
import os

import yaml

from security_gateway import detection, supervisor_agent

_SKILL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "skills", "authentication", "brute-force",
)


def _load_fixtures():
    with open(os.path.join(_SKILL_DIR, "tests", "fixtures.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_brute_force_fixtures():
    for case in _load_fixtures():
        evidence = case["evidence"]
        skill_id = supervisor_agent.route_authentication(evidence)
        assert skill_id == case["expected_skill"], case["name"]

        floor_action, _reason = detection.apply_floor("authentication", skill_id, evidence)
        assert floor_action == case["expected_floor_action"], case["name"]


def test_brute_force_example_attack():
    with open(os.path.join(_SKILL_DIR, "examples", "example_attack.yaml"), encoding="utf-8") as f:
        example = yaml.safe_load(f)

    evidence = example["evidence"]
    skill_id = supervisor_agent.route_authentication(evidence)
    assert skill_id == example["expected"]["routed_skill"]

    floor_action, _reason = detection.apply_floor("authentication", skill_id, evidence)
    assert (floor_action is not None) == example["expected"]["floor_triggered"]
    if example["expected"]["floor_triggered"]:
        assert floor_action == example["expected"]["minimum_action"]
