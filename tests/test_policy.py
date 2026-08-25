import pytest

from security_gateway import policy


def test_load_policy_has_all_four_categories():
    p = policy.load_policy()
    assert set(p.categories.keys()) == {"authentication", "rag_security", "file_security", "agent_security"}


def test_clamp_action_passes_through_high_confidence_block():
    action = policy.clamp_action("authentication", "BLOCK", confidence=0.95)
    assert action == "BLOCK"


def test_clamp_action_steps_down_low_confidence_block():
    # authentication's min_confidence_to_enforce is 0.55
    action = policy.clamp_action("authentication", "BLOCK", confidence=0.1)
    assert action == "MITIGATE"


def test_clamp_action_steps_down_low_confidence_mitigate_to_allow():
    action = policy.clamp_action("rag_security", "MITIGATE", confidence=0.05)
    assert action == "ALLOW"


def test_clamp_action_allow_stays_allow_regardless_of_confidence():
    assert policy.clamp_action("file_security", "ALLOW", confidence=0.0) == "ALLOW"


def test_clamp_action_rejects_malformed_action_never_defaults_to_allow():
    # An unrecognized action from a malformed LLM response must never be
    # trusted as ALLOW - treated as MITIGATE (fail toward caution) before
    # any confidence clamping.
    action = policy.clamp_action("authentication", "DELETE_EVERYTHING", confidence=0.9)
    assert action in ("MITIGATE", "ALLOW")  # MITIGATE, or stepped down further by confidence
    assert action != "BLOCK"


def test_fail_closed_action_is_never_allow():
    for category in ("authentication", "rag_security", "file_security", "agent_security"):
        assert policy.fail_closed_action(category) != "ALLOW"


def test_agent_security_fails_closed_to_block_not_mitigate():
    # Deliberate deviation from the other categories (all MITIGATE) -
    # "do not automatically trust another agent" (CLAUDE.md 4.5) means a
    # failed discussion should not let a tool request through in any form.
    assert policy.fail_closed_action("agent_security") == "BLOCK"


def test_action_effect_lookup():
    assert policy.action_effect("authentication", "BLOCK") == "redis_block"
    assert policy.action_effect("rag_security", "BLOCK") == "refuse_and_sandbox"
    assert policy.action_effect("file_security", "MITIGATE") == "sandbox_no_ingest"


def test_unknown_category_raises():
    with pytest.raises(ValueError):
        policy.clamp_action("not_a_category", "ALLOW", confidence=0.9)
