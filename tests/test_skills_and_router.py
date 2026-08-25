import pytest

from security_gateway import detection, skills, threat_router


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


def test_route_authentication_defaults_to_brute_force_on_no_signal():
    assert threat_router.route_authentication({}) == "brute-force"


def test_route_authentication_selects_credential_stuffing():
    evidence = {"distinct_usernames_from_source_5min": 5}
    assert threat_router.route_authentication(evidence) == "credential-stuffing"


def test_route_authentication_selects_account_takeover():
    evidence = {"this_attempt_success": True, "failed_attempts": 4}
    assert threat_router.route_authentication(evidence) == "account-takeover"


def test_route_authentication_does_not_select_account_takeover_on_failure():
    evidence = {"this_attempt_success": False, "failed_attempts": 10}
    assert threat_router.route_authentication(evidence) == "brute-force"


def test_route_files_defaults_to_malicious_pdf():
    assert threat_router.route_files({"extension": ".md"}) == "malicious-pdf"
    assert threat_router.route_files({"extension": ".pdf"}) == "malicious-pdf"
    assert threat_router.route_files({"extension": ".xlsx"}) == "malicious-pdf"


def test_route_files_selects_docx():
    assert threat_router.route_files({"extension": ".docx"}) == "malicious-docx"


def test_route_files_selects_archive_bomb():
    assert threat_router.route_files({"extension": ".zip"}) == "archive-bomb"


def test_route_chat_always_includes_baseline_defaults():
    selected = threat_router.route_chat({})
    categories = {cat for cat, _sid in selected}
    skill_ids = {sid for _cat, sid in selected}
    assert categories == {"llm", "rag"}
    assert "prompt-injection" in skill_ids
    assert "rag-poisoning" in skill_ids


def test_route_chat_adds_jailbreak_on_override_language():
    selected = threat_router.route_chat({"question_has_override_language": True})
    skill_ids = {sid for _cat, sid in selected}
    assert "jailbreak" in skill_ids
    assert "prompt-injection" in skill_ids  # baseline default is NOT dropped when jailbreak fires


def test_route_chat_adds_model_extraction_and_retrieval_manipulation():
    selected = threat_router.route_chat({
        "question_has_extraction_language": True,
        "question_targets_retrieval_params": True,
    })
    skill_ids = {sid for _cat, sid in selected}
    assert "model-extraction" in skill_ids
    assert "retrieval-manipulation" in skill_ids


def test_route_chat_adds_pii_exposure_when_context_has_pii():
    selected = threat_router.route_chat({"context_contains_pii": True, "pii_types_found": ["phone"]})
    skill_ids = {sid for _cat, sid in selected}
    assert "pii-exposure" in skill_ids
    assert "rag-poisoning" in skill_ids  # baseline still included alongside it


def test_route_chat_no_pii_exposure_on_clean_context():
    selected = threat_router.route_chat({"context_contains_pii": False})
    skill_ids = {sid for _cat, sid in selected}
    assert "pii-exposure" not in skill_ids


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


def test_route_chat_adds_external_api_abuse_when_external_search_used():
    selected = threat_router.route_chat({"external_search_used": True})
    skill_ids = {sid for _cat, sid in selected}
    assert "external-api-abuse" in skill_ids
    assert "rag-poisoning" in skill_ids  # baseline still included alongside it


def test_route_chat_no_external_api_abuse_when_no_external_search():
    selected = threat_router.route_chat({"external_search_used": False})
    skill_ids = {sid for _cat, sid in selected}
    assert "external-api-abuse" not in skill_ids


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


def test_route_agents_always_includes_tool_abuse_baseline():
    selected = threat_router.route_agents({"tool_in_registered_set": True, "role_changed": False})
    assert selected == [("agents", "tool-abuse")]


def test_route_agents_adds_privilege_escalation_on_unaudited_role_change():
    evidence = {
        "tool_in_registered_set": True,
        "role_changed": True,
        "role_change_event_id": None,
    }
    selected = threat_router.route_agents(evidence)
    skill_ids = {sid for _cat, sid in selected}
    assert skill_ids == {"tool-abuse", "privilege-escalation"}


def test_route_agents_no_privilege_escalation_when_roles_match():
    evidence = {
        "tool_in_registered_set": True,
        "role_changed": False,
        "role_change_event_id": None,
    }
    selected = threat_router.route_agents(evidence)
    skill_ids = {sid for _cat, sid in selected}
    assert skill_ids == {"tool-abuse"}


def test_route_agents_no_privilege_escalation_when_role_change_audited():
    evidence = {
        "tool_in_registered_set": True,
        "role_changed": True,
        "role_change_event_id": 42,
    }
    selected = threat_router.route_agents(evidence)
    skill_ids = {sid for _cat, sid in selected}
    assert skill_ids == {"tool-abuse"}


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
