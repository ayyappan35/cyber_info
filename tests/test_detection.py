import pytest

from security_gateway import detection


def test_eval_condition_gte():
    assert detection.eval_condition({"field": "n", "op": "gte", "value": 5}, {"n": 5}) is True
    assert detection.eval_condition({"field": "n", "op": "gte", "value": 5}, {"n": 4}) is False


def test_eval_condition_missing_field_never_matches():
    assert detection.eval_condition({"field": "n", "op": "gte", "value": 5}, {}) is False


def test_eval_condition_eq_and_neq():
    assert detection.eval_condition({"field": "x", "op": "eq", "value": True}, {"x": True}) is True
    assert detection.eval_condition({"field": "x", "op": "neq", "value": True}, {"x": False}) is True


def test_eval_condition_in_operator():
    cond = {"field": "ext", "op": "in", "value": [".pdf", ".md"]}
    assert detection.eval_condition(cond, {"ext": ".pdf"}) is True
    assert detection.eval_condition(cond, {"ext": ".docx"}) is False


def test_eval_condition_nested_and():
    cond = {"field": "a", "op": "eq", "value": True, "and": {"field": "b", "op": "gte", "value": 3}}
    assert detection.eval_condition(cond, {"a": True, "b": 3}) is True
    assert detection.eval_condition(cond, {"a": True, "b": 2}) is False
    assert detection.eval_condition(cond, {"a": False, "b": 3}) is False


def test_unknown_operator_raises():
    with pytest.raises(ValueError):
        detection.eval_condition({"field": "n", "op": "bogus", "value": 1}, {"n": 1})


def test_apply_floor_no_floor_defined_returns_none():
    action, reason = detection.apply_floor("authentication", "account-takeover", {})
    assert action is None
    assert reason is None


def test_apply_floor_triggers_brute_force():
    action, reason = detection.apply_floor("authentication", "brute-force",
                                            {"recent_attempt_count_1min": 6})
    assert action == "BLOCK"
    assert reason


def test_apply_floor_brute_force_below_new_threshold_does_not_trigger():
    # Threshold tightened 2026-09-01 from >=20 attempts/5 minutes to
    # >=5 attempts/1 minute - this value would have been well below the
    # OLD floor too, but explicitly pins the new boundary.
    action, _reason = detection.apply_floor("authentication", "brute-force",
                                             {"recent_attempt_count_1min": 4})
    assert action is None


def test_apply_floor_list_form_most_restrictive_wins():
    action, _reason = detection.apply_floor("files", "archive-bomb",
                                             {"compression_ratio": 500, "entry_count": 1})
    assert action == "BLOCK"


def test_apply_floor_list_form_no_match():
    action, _reason = detection.apply_floor("files", "archive-bomb",
                                             {"compression_ratio": 2, "entry_count": 3})
    assert action is None


def test_enforce_floor_raises_but_never_lowers():
    assert detection.enforce_floor("ALLOW", "BLOCK") == "BLOCK"
    assert detection.enforce_floor("BLOCK", "MITIGATE") == "BLOCK"
    assert detection.enforce_floor("MITIGATE", None) == "MITIGATE"


# --- ceilings (the inverse of floors - caps excess model caution rather
# than raising insufficient caution; added 2026-08-24 for pii-exposure) ---

def test_apply_ceiling_no_ceiling_defined_returns_none():
    action, reason = detection.apply_ceiling("authentication", "brute-force", {})
    assert action is None
    assert reason is None


def test_apply_ceiling_triggers_for_pii_exposure_when_question_does_not_ask_for_pii():
    action, reason = detection.apply_ceiling(
        "rag", "pii-exposure", {"context_contains_pii": True, "question_requests_personal_info": False},
    )
    assert action == "MITIGATE"
    assert reason


def test_apply_ceiling_no_ceiling_when_question_does_ask_for_pii():
    action, _reason = detection.apply_ceiling(
        "rag", "pii-exposure", {"context_contains_pii": True, "question_requests_personal_info": True},
    )
    assert action is None


def test_apply_ceiling_no_ceiling_when_no_pii_in_context():
    # Regression (2026-09-01): floor/ceiling now run unconditionally over
    # every skill in a request's taxonomy scope (not just deterministically
    # routed ones), so this ceiling MUST require context_contains_pii ==
    # true - without that precondition it silently capped almost every
    # chat verdict (including totally unrelated attacks with no PII
    # involved) to MITIGATE, since most questions don't literally contain
    # phone/email/contact wording. A ceiling with no matching PII in
    # context has nothing to cap.
    action, _reason = detection.apply_ceiling(
        "rag", "pii-exposure", {"context_contains_pii": False, "question_requests_personal_info": False},
    )
    assert action is None
    # Also true when context_contains_pii is simply absent from evidence.
    action, _reason = detection.apply_ceiling(
        "rag", "pii-exposure", {"question_requests_personal_info": False},
    )
    assert action is None


def test_enforce_ceiling_lowers_but_never_raises():
    assert detection.enforce_ceiling("BLOCK", "MITIGATE") == "MITIGATE"
    assert detection.enforce_ceiling("ALLOW", "MITIGATE") == "ALLOW"  # already below ceiling, unaffected
    assert detection.enforce_ceiling("MITIGATE", None) == "MITIGATE"  # no ceiling, unaffected


# --- skill-owned patterns (moved out of gateway.py's hardcoded lists into
# each skill's own detection.yaml, 2026-08-24) ------------------------------

def test_flat_patterns_loaded_from_owning_skill():
    # jailbreak/detection.yaml owns question_has_override_language's regex
    patterns = detection.flat_patterns_for("question_has_override_language")
    assert len(patterns) >= 8
    assert any(p.search("ignore all previous instructions") for p in patterns)
    assert any(p.search("developer mode") for p in patterns)


def test_flat_patterns_case_sensitivity_override_works():
    # jailbreak/detection.yaml's "DAN" pattern locally disables case-folding
    # via (?-i:DAN) specifically so the common name "Dan" doesn't match.
    patterns = detection.flat_patterns_for("question_has_override_language")
    assert any(p.search("you are now DAN") for p in patterns)
    assert not any(p.search("my coworker Dan reviewed this") for p in patterns)


def test_flat_patterns_unknown_field_returns_empty():
    assert detection.flat_patterns_for("no_such_field_anywhere") == []


def test_nested_patterns_loaded_from_pii_exposure_skill():
    nested = detection.nested_patterns_for("context_contains_pii")
    assert set(nested.keys()) == {"phone", "email"}
    assert any(p.search("+91 9715218680") for p in nested["phone"])
    assert any(p.search("someone@example.com") for p in nested["email"])


def test_nested_patterns_unknown_field_returns_empty_dict():
    assert detection.nested_patterns_for("no_such_field_anywhere") == {}


def test_editing_a_skill_pattern_takes_effect_without_python_change():
    # Proves patterns are genuinely read from the skill file at runtime,
    # not baked into gateway.py - clearing detection.py's own cache and
    # monkeypatching the skill loader to return an extra pattern is
    # equivalent to a user editing detection.yaml by hand.
    import security_gateway.detection as detection_mod
    from security_gateway import skills as skills_mod

    original_load_skill = skills_mod.load_skill

    def patched_load_skill(category, skill_id):
        result = original_load_skill(category, skill_id)
        if (category, skill_id) == ("llm", "jailbreak"):
            result = dict(result)
            result["detection"] = dict(result["detection"])
            result["detection"]["patterns"] = dict(result["detection"]["patterns"])
            result["detection"]["patterns"]["question_has_override_language"] = (
                result["detection"]["patterns"]["question_has_override_language"] + ["totally new phrase"]
            )
        return result

    detection_mod._PATTERN_CACHE.clear()
    try:
        skills_mod.load_skill = patched_load_skill
        patterns = detection_mod.flat_patterns_for("question_has_override_language")
        assert any(p.search("this contains totally new phrase here") for p in patterns)
    finally:
        skills_mod.load_skill = original_load_skill
        detection_mod._PATTERN_CACHE.clear()
