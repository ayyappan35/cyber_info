import pytest
from pydantic import ValidationError

from security_gateway.decision import SecurityDecision


def test_valid_decision():
    d = SecurityDecision(action="BLOCK", confidence=0.9, threat_indicators=["x"], reasoning="clear pattern")
    assert d.action == "BLOCK"


def test_confidence_out_of_range_rejected():
    with pytest.raises(ValidationError):
        SecurityDecision(action="ALLOW", confidence=1.5, threat_indicators=[], reasoning="ok")


def test_invalid_action_literal_rejected():
    with pytest.raises(ValidationError):
        SecurityDecision(action="MAYBE", confidence=0.5, threat_indicators=[], reasoning="ok")


def test_empty_reasoning_rejected():
    with pytest.raises(ValidationError):
        SecurityDecision(action="ALLOW", confidence=0.5, threat_indicators=[], reasoning="")


def test_threat_indicators_defaults_to_empty_list():
    d = SecurityDecision(action="ALLOW", confidence=0.5, reasoning="nothing suspicious")
    assert d.threat_indicators == []


def test_matched_skill_ids_defaults_to_empty_list():
    d = SecurityDecision(action="ALLOW", confidence=0.5, reasoning="nothing suspicious")
    assert d.matched_skill_ids == []


def test_matched_skill_ids_accepts_reported_skills():
    d = SecurityDecision(action="BLOCK", confidence=0.9, reasoning="pii disclosure",
                          matched_skill_ids=["pii-exposure"])
    assert d.matched_skill_ids == ["pii-exposure"]
