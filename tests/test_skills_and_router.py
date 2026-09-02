import pytest

from security_gateway import detection, skills, supervisor_agent


def test_all_taxonomy_skills_load():
    for category, skill_ids in skills.CATEGORY_SKILLS.items():
        for skill_id in skill_ids:
            skill = skills.load_skill(category, skill_id)
            assert skill["content"]
            assert skill["frontmatter"]["skill_id"] == skill_id
            assert skill["frontmatter"]["category"] == category


def test_every_wired_skill_has_detection_yaml():
    for category, skill_ids in skills.CATEGORY_SKILLS.items():
        for skill_id in skill_ids:
            skill = skills.load_skill(category, skill_id)
            assert skill["detection"], f"{category}/{skill_id} missing detection.yaml content"


def test_agents_skills_wiring_status():
    # 2026-08-24: tool-abuse and privilege-escalation are real, wired to
    # request_category="agent_security" (see security_gateway/gateway.py).
    # intent-drift stays honestly unwired - see its SKILL.md for why
    # (needs a goal_alignment_score this build doesn't compute).
    assert skills.load_skill("agents", "tool-abuse")["detection"].get("wired") is True
    assert skills.load_skill("agents", "privilege-escalation")["detection"].get("wired") is True
    assert skills.load_skill("agents", "intent-drift")["detection"].get("wired") is False


def test_exactly_one_default_skill_per_dispatch_category():
    for category in ("authentication", "llm", "rag", "files", "agents"):
        defaults = [sid for sid in skills.CATEGORY_SKILLS[category]
                    if skills.load_skill(category, sid)["detection"].get("default")]
        assert len(defaults) == 1, f"category '{category}' must have exactly one default skill"


def test_unknown_category_raises():
    with pytest.raises(ValueError):
        skills.load_skill("not_a_real_category", "x")


def test_unknown_skill_in_known_category_raises():
    with pytest.raises(ValueError):
        skills.load_skill("authentication", "not-a-real-skill")


def test_pii_exposure_floor_forces_block_when_question_asks_for_it():
    action, reason = detection.apply_floor(
        "rag", "pii-exposure",
        {"context_contains_pii": True, "question_requests_personal_info": True},
    )
    assert action == "BLOCK"
    assert reason


def test_pii_exposure_no_floor_without_pii():
    action, _reason = detection.apply_floor(
        "rag", "pii-exposure",
        {"context_contains_pii": False, "question_requests_personal_info": True},
    )
    assert action is None


def test_pii_exposure_regression_unrelated_question_not_blocked():
    # Real observed false-positive (2026-08-24): a chunk containing PII
    # anywhere must not force BLOCK on a question that isn't asking for
    # that PII - "what's his top skill set" retrieved the same resume
    # chunk as "what's his phone number" but must not be treated the same.
    action, _reason = detection.apply_floor(
        "rag", "pii-exposure",
        {"context_contains_pii": True, "question_requests_personal_info": False},
    )
    assert action is None


def test_external_api_abuse_floor_blocks_ssrf_shaped_query():
    action, reason = detection.apply_floor(
        "rag", "external-api-abuse", {"external_query_targets_internal_host": True},
    )
    assert action == "BLOCK"
    assert reason


def test_external_api_abuse_floor_mitigates_exfiltration_shaped_query():
    action, reason = detection.apply_floor(
        "rag", "external-api-abuse", {"external_query_looks_like_exfiltration": True},
    )
    assert action == "MITIGATE"
    assert reason


def test_external_api_abuse_no_floor_on_clean_query():
    action, _reason = detection.apply_floor(
        "rag", "external-api-abuse",
        {"external_query_targets_internal_host": False, "external_query_looks_like_exfiltration": False},
    )
    assert action is None


def test_external_api_abuse_floor_blocks_question_directing_exfiltration():
    # Real, observed attempt (2026-09-01): the QUESTION itself instructing
    # the assistant to call an external API and exfiltrate data - no tool
    # call needs to have happened for this floor to fire.
    action, reason = detection.apply_floor(
        "rag", "external-api-abuse", {"question_directs_data_exfiltration": True},
    )
    assert action == "BLOCK"
    assert reason


# --- supervisor_agent.all_skills_for() - the Supervisor Agent's Skills
# output: the FULL taxonomy scope for a request_category, unconditional,
# no filtering. gateway.py feeds every one of these skills' SKILL.md
# content into the single Security LLM call, which alone decides
# relevance (llm_discussion.py) - see supervisor_agent.py's module
# docstring for why this replaced regex-based pre-selection. ---

def test_all_skills_for_authentication_is_every_authentication_skill():
    selected = supervisor_agent.all_skills_for("authentication")
    assert {sid for _cat, sid in selected} == {
        "credential-stuffing", "account-takeover", "brute-force", "password-spraying",
    }
    assert {cat for cat, _sid in selected} == {"authentication"}


def test_all_skills_for_rag_security_spans_llm_and_rag_categories():
    selected = supervisor_agent.all_skills_for("rag_security")
    skill_ids = {sid for _cat, sid in selected}
    assert skill_ids == {"jailbreak", "model-extraction", "prompt-injection",
                          "pii-exposure", "external-api-abuse", "retrieval-manipulation", "rag-poisoning"}
    assert {cat for cat, _sid in selected} == {"llm", "rag"}


def test_all_skills_for_is_unconditional_regardless_of_evidence():
    # No regex/condition filtering happens here anymore - the full set is
    # identical no matter what the (irrelevant, unused) evidence would be,
    # because this function doesn't take evidence as an input at all.
    assert supervisor_agent.all_skills_for("file_security") == supervisor_agent.all_skills_for("file_security")
    assert {sid for _cat, sid in supervisor_agent.all_skills_for("file_security")} == \
        {"archive-bomb", "malicious-docx", "malicious-pdf"}


def test_all_skills_for_unknown_request_category_raises():
    with pytest.raises(ValueError):
        supervisor_agent.all_skills_for("not_a_real_category")


def test_password_spraying_floor_blocks_shared_password_across_accounts():
    action, reason = detection.apply_floor(
        "authentication", "password-spraying", {"distinct_usernames_same_password_5min": 5},
    )
    assert action == "BLOCK"
    assert reason


def test_password_spraying_no_floor_below_threshold():
    action, _reason = detection.apply_floor(
        "authentication", "password-spraying", {"distinct_usernames_same_password_5min": 4},
    )
    assert action is None


def test_tool_abuse_floor_blocks_out_of_scope_tool_request():
    action, reason = detection.apply_floor("agents", "tool-abuse", {"tool_in_registered_set": False})
    assert action == "BLOCK"
    assert reason


def test_tool_abuse_no_floor_when_tool_in_scope():
    action, _reason = detection.apply_floor("agents", "tool-abuse", {"tool_in_registered_set": True})
    assert action is None


def test_privilege_escalation_floor_blocks_unaudited_role_change():
    action, reason = detection.apply_floor("agents", "privilege-escalation", {
        "role_changed": True, "role_change_event_id": None,
    })
    assert action == "BLOCK"
    assert reason


def test_privilege_escalation_no_floor_when_roles_match():
    action, _reason = detection.apply_floor("agents", "privilege-escalation", {
        "role_changed": False, "role_change_event_id": None,
    })
    assert action is None


def test_privilege_escalation_no_floor_when_change_is_audited():
    action, _reason = detection.apply_floor("agents", "privilege-escalation", {
        "role_changed": True, "role_change_event_id": 7,
    })
    assert action is None
