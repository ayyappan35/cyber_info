"""AI Security Gateway - the single entrypoint the architecture diagram
describes end to end:

    USER REQUEST -> Threat Router -> one or more taxonomy skills
    (skills/<category>/<skill-id>/) -> Security LLM Discussion ->
    SECURITY DECISION (ALLOW/MITIGATE/BLOCK, raised to any matching
    skill's deterministic floor) -> MCP Tools (Redis/SIEM/Sandbox) ->
    verified.

Every request path (auth login, chat query, file upload) calls
`analyze()` with a fixed `request_category` ("authentication",
"rag_security", "file_security" - matching policies/
security_gateway_policy.yaml's enforcement config) and evidence it
gathered itself. Internally, `analyze()` uses `threat_router.py` to
resolve WHICH specific taxonomy skill(s) apply (e.g. authentication's
request_category resolves to exactly one of brute-force/
credential-stuffing/account-takeover), builds one combined Security LLM
Discussion prompt from all matched skills' SKILL.md content, then
enforces every matched skill's detection.yaml floor before the policy
clamp is applied.
"""
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PIPELINES_DIR = os.path.join(_PROJECT_ROOT, "backend", "pipelines")
if _PIPELINES_DIR not in sys.path:
    sys.path.insert(0, _PIPELINES_DIR)

from security_gateway import agent_registry, chain_detection, detection, mcp_gateway, policy, threat_router
from security_gateway import skills as skills_mod
from security_gateway.decision import SecurityDecision
from security_gateway.llm_discussion import DiscussionFailed, discuss
from security_gateway.mcp_tools import redis_tool, sandbox_tool, siem_tool

_ACTION_RANK = {"ALLOW": 0, "MITIGATE": 1, "BLOCK": 2}


@dataclass
class GatewayResult:
    category: str
    action: str
    raw_action: Optional[str]
    confidence: float
    threat_indicators: list
    reasoning: str
    skill_ids: list = field(default_factory=list)
    floor_triggered: Optional[str] = None
    sandbox_id: Optional[str] = None
    blocked_identity: bool = False
    verified: bool = True
    decision_id: Optional[int] = None
    fail_closed: bool = False
    tool_results: list = field(default_factory=list)   # list of mcp_gateway.ToolResult
    chain: Optional[dict] = None                        # chain_detection.detect_chain()'s return


def _resolve_skills(request_category: str, evidence: dict) -> list:
    """Returns a list of (taxonomy_category, skill_id) tuples selected for
    this request."""
    if request_category == "authentication":
        return [("authentication", threat_router.route_authentication(evidence))]
    if request_category == "file_security":
        return [("files", threat_router.route_files(evidence))]
    if request_category == "rag_security":
        return threat_router.route_chat(evidence)
    if request_category == "agent_security":
        return threat_router.route_agents(evidence)
    raise ValueError(f"Unknown request_category '{request_category}'")


def _search_threat_knowledge(skill_ids: list) -> list:
    try:
        from threat_knowledge import search_threat_knowledge
        query = " ".join(sid.replace("-", " ") for sid in skill_ids)
        return search_threat_knowledge(query, top_k=4)
    except Exception:
        # Best-effort grounding - retrieval failing must never block the
        # gateway itself; the discussion still runs, just without it.
        return []


async def analyze(request_category: str, identity: str, evidence: dict, *,
                   sandbox_payload: Optional[dict] = None,
                   model: str = None, log=print) -> GatewayResult:
    """sandbox_payload, if given, is either
    {"kind": "text", "content": str} or
    {"kind": "file", "filename": str, "raw": bytes, "text_sample": str} -
    only actually written to the sandbox if the enforced action's policy
    effect calls for it."""
    selected = _resolve_skills(request_category, evidence)
    skill_ids = [sid for _cat, sid in selected]
    loaded_skills = [skills_mod.load_skill(cat, sid) for cat, sid in selected]
    retrieved = _search_threat_knowledge(skill_ids)
    primary_skill = selected[0]

    available_tools = mcp_gateway.tools_for_category(request_category)

    fail_closed = False
    proposed_tools = []
    try:
        decision: SecurityDecision = await discuss(request_category, loaded_skills, evidence, retrieved,
                                                     available_tools=available_tools, model=model, log=log)
        raw_action, confidence = decision.action, decision.confidence
        threat_indicators, reasoning = decision.threat_indicators, decision.reasoning
        action = policy.clamp_action(request_category, raw_action, confidence, skill=primary_skill)
        # Hallucinated/out-of-catalog tool names are dropped here rather
        # than failing the whole decision - a malformed tool proposal must
        # never take down an otherwise-valid ALLOW/MITIGATE/BLOCK verdict.
        proposed_tools = [t for t in decision.required_tools if t in available_tools]
    except DiscussionFailed as e:
        fail_closed = True
        raw_action, confidence = None, 0.0
        threat_indicators = ["security_llm_discussion_failed"]
        reasoning = f"Security LLM Discussion node failed after retries ({e}); failing closed per policy."
        action = policy.fail_closed_action(request_category)

    # Deterministic floors (security_gateway/detection.py): the most
    # restrictive matching floor across ALL selected skills raises (never
    # lowers) the action - a real security-boundary control the LLM
    # cannot weaken, per CLAUDE.md section 8.
    floor_action, floor_reason, floor_skill = None, None, None
    for cat, sid in selected:
        fa, reason = detection.apply_floor(cat, sid, evidence)
        if fa is not None and (floor_action is None or _ACTION_RANK[fa] > _ACTION_RANK[floor_action]):
            floor_action, floor_reason, floor_skill = fa, f"[{sid}] {reason}", (cat, sid)
    if floor_action is not None:
        pre_floor_action = action
        action = detection.enforce_floor(action, floor_action)
        if action != pre_floor_action:
            reasoning = f"{reasoning} | Deterministic floor raised action to {action}: {floor_reason}"

    # Deterministic ceilings: the opposite correction - the most
    # restrictive matching ceiling across ALL selected skills caps (never
    # raises) the action, but never below what an INDEPENDENT floor above
    # already demands (a real attack another skill's floor caught must
    # never be waved through because an unrelated skill's ceiling also
    # matched). See security_gateway/detection.py::apply_ceiling's
    # docstring for why this exists - repeated, observed over-blocking on
    # skills/rag/pii-exposure that SKILL.md wording alone didn't fix.
    ceiling_action, ceiling_reason, ceiling_skill = None, None, None
    for cat, sid in selected:
        ca, reason = detection.apply_ceiling(cat, sid, evidence)
        if ca is not None and (ceiling_action is None or _ACTION_RANK[ca] < _ACTION_RANK[ceiling_action]):
            ceiling_action, ceiling_reason, ceiling_skill = ca, f"[{sid}] {reason}", (cat, sid)
    if ceiling_action is not None and (floor_action is None or _ACTION_RANK[ceiling_action] >= _ACTION_RANK[floor_action]):
        pre_ceiling_action = action
        action = detection.enforce_ceiling(action, ceiling_action)
        if action != pre_ceiling_action:
            reasoning = f"{reasoning} | Deterministic ceiling capped action to {action}: {ceiling_reason}"

    # Whichever skill's floor/ceiling actually matched governs the
    # enforcement effect (response.yaml), NOT just `selected[0]` - for a
    # multi-skill chat request, selected[0] is always the llm/ category's
    # baseline skill (e.g. prompt-injection), which would silently skip
    # e.g. rag/pii-exposure's response.yaml override even when ITS
    # floor/ceiling is what produced this outcome. A real bug, found and
    # fixed 2026-08-24 for floors, extended to ceilings the same day.
    effect_skill = floor_skill or ceiling_skill or primary_skill
    effect = policy.action_effect(request_category, action, skill=effect_skill)
    sandbox_id = None
    blocked_identity = False

    if effect == "tool_approval_required" and "disclose_pii_answer" not in proposed_tools:
        # Deterministic, not LLM-proposed (skills/rag/pii-exposure's
        # response.yaml sets this effect specifically to bypass the
        # passive sandbox-and-forget path): whenever a skill's response.yaml
        # asks for real admin approval before disclosure, the tool
        # proposal happens here regardless of what the LLM itself proposed.
        proposed_tools = proposed_tools + ["disclose_pii_answer"]

    if effect in ("sandbox_and_continue", "sandbox_no_ingest", "refuse_and_sandbox", "reject_and_sandbox"):
        if sandbox_payload and sandbox_payload.get("kind") == "file":
            sandbox_id = sandbox_tool.quarantine_file(
                request_category, identity, sandbox_payload["filename"], sandbox_payload["raw"],
                sandbox_payload.get("text_sample", ""),
                metadata={"reasoning": reasoning, "action": action, "skill_ids": skill_ids},
            )
        else:
            content = sandbox_payload["content"] if sandbox_payload else json.dumps(evidence, default=str)
            sandbox_id = sandbox_tool.quarantine_text(
                request_category, identity, content,
                metadata={"reasoning": reasoning, "action": action, "skill_ids": skill_ids},
            )

    if effect == "redis_block":
        ttl = policy.action_config_value(request_category, action, "block_ttl_seconds",
                                          skill=effect_skill, default=900)
        redis_tool.block_identity(identity, request_category, reasoning, ttl_seconds=ttl)
        blocked_identity = True

    verified = _verify(request_category, identity, sandbox_id, blocked_identity)

    decision_id = siem_tool.log_decision(
        category=request_category, identity=identity, action=action, raw_action=raw_action,
        confidence=confidence, threat_indicators=threat_indicators, reasoning=reasoning,
        enforced=verified, sandbox_id=sandbox_id, skill_ids=skill_ids,
    )
    siem_tool.log_event(agent_id="security_gateway", tool_name=f"analyze:{request_category}",
                         decision=action,
                         risk=("high" if action == "BLOCK" else "medium" if action == "MITIGATE" else "low"),
                         detail=f"skills={skill_ids} | {reasoning}")

    # MCP Tool Authorization Gateway: each tool the LLM proposed goes
    # through its own independent authorization (category scope, rate
    # limit, requires_approval) - the LLM's proposal is never trusted as
    # sufficient authorization by itself.
    tool_results = [
        mcp_gateway.authorize_and_execute(name, request_category, identity, evidence, decision_id=decision_id)
        for name in proposed_tools
    ]

    # Attack-chain detection: purely a read over history just logged above
    # (this decision is already included) - never blocks/changes this
    # request's own outcome, only surfaces the pattern for the dashboard.
    chain = chain_detection.detect_chain(identity)
    if chain["chained"]:
        siem_tool.log_event(agent_id="security_gateway", tool_name="chain_detection",
                             decision="ATTACK_CHAIN_DETECTED",
                             detail=f"identity={identity} skills={chain['skill_ids']} "
                                    f"categories={chain['categories']}")

    return GatewayResult(category=request_category, action=action, raw_action=raw_action, confidence=confidence,
                          threat_indicators=threat_indicators, reasoning=reasoning, skill_ids=skill_ids,
                          floor_triggered=floor_action, sandbox_id=sandbox_id, blocked_identity=blocked_identity,
                          verified=verified, decision_id=decision_id, fail_closed=fail_closed,
                          tool_results=tool_results, chain=chain)


def _verify(request_category: str, identity: str, sandbox_id: Optional[str], blocked_identity: bool) -> bool:
    """Re-reads ground truth rather than trusting the enforcement calls
    above didn't raise - CLAUDE.md 4.11: never report an action successful
    without verification evidence."""
    if blocked_identity and not redis_tool.is_blocked(identity, request_category):
        return False
    if sandbox_id and sandbox_tool.get(sandbox_id) is None:
        return False
    return True


# --- evidence gathering helpers -------------------------------------------
# Kept here (not in the routers) so every category's evidence shape is
# defined in one place, next to the skills it feeds.

def gather_authentication_evidence(username: str, source_ip: str, account_exists: bool, failed_attempts: int,
                                    locked: bool, this_attempt_success: bool) -> dict:
    redis_tool.record_attempt(username)
    redis_tool.record_username_attempt(source_ip, username)
    return {
        "username": username,
        "source_ip": source_ip,
        "account_exists": account_exists,
        "failed_attempts": failed_attempts,
        "account_locked": locked,
        "recent_attempt_count_5min": redis_tool.get_attempt_count(username),
        "distinct_usernames_from_source_5min": redis_tool.get_distinct_usernames(source_ip),
        "already_blocked": redis_tool.is_blocked(username, "authentication"),
        "this_attempt_success": this_attempt_success,
    }


_PDF_ACTIVE_CONTENT_MARKERS = (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA")


def gather_file_security_evidence(filename: str, raw: bytes, text_sample: str,
                                   uploaded_by: str, recent_uploads_by_uploader: int) -> dict:
    from security_gateway.archive_scan import is_zip, scan_zip_structure

    ext = os.path.splitext(filename)[1].lower()
    markers = [m.decode() for m in _PDF_ACTIVE_CONTENT_MARKERS if m in raw] if ext == ".pdf" else []

    evidence = {
        "filename": filename,
        "extension": ext,
        "size_bytes": len(raw),
        "uploaded_by": uploaded_by,
        "recent_uploads_by_uploader": recent_uploads_by_uploader,
        "pdf_active_content_markers": markers,
        "pdf_marker_count": len(markers),
        "text_sample": text_sample[:4000],
        "macro_present": False,
        "compression_ratio": 0.0,
        "entry_count": 0,
    }
    if is_zip(raw):
        archive = scan_zip_structure(raw)
        evidence.update({
            "macro_present": archive.get("macro_present", False),
            "compression_ratio": archive.get("compression_ratio", 0.0),
            "entry_count": archive.get("entry_count", 0),
        })
    return evidence


# --- deterministic chat-evidence regex signals ---------------------------
# The actual regex TEXT lives in each owning skill's detection.yaml (e.g.
# skills/llm/jailbreak/detection.yaml's `patterns.question_has_override_
# language`) - detection.py::flat_patterns_for()/nested_patterns_for()
# load and compile it from there. This module only computes the booleans
# from whatever patterns the skills declare; it no longer hardcodes the
# pattern text itself, so editing a skill's detection.yaml (e.g. adding a
# new phone-number format) takes effect with no Python change. Never a
# standalone verdict either way (CLAUDE.md section 8) - only jailbreak/
# model-extraction/rag-poisoning/pii-exposure's detection.yaml floors
# treat a hit as a deterministic minimum, never as BLOCK by itself (except
# pii-exposure, which is deliberately the one exception - see its SKILL.md).


def _any_match(patterns, text: str) -> bool:
    return any(p.search(text) for p in patterns)


def _detect_pii(text: str) -> list:
    nested = detection.nested_patterns_for("context_contains_pii")
    return [kind for kind, patterns in nested.items() if _any_match(patterns, text)]


def gather_chat_evidence(question: str, retrieved_context: str, sources: list,
                          external_queries: Optional[list] = None) -> dict:
    pii_types_found = _detect_pii(retrieved_context)
    external_queries = external_queries or []
    external_query_text = " ".join(external_queries)
    return {
        "question": question,
        "retrieved_context": retrieved_context[:6000],
        "sources": sources,
        "question_has_override_language": _any_match(
            detection.flat_patterns_for("question_has_override_language"), question),
        "question_has_extraction_language": _any_match(
            detection.flat_patterns_for("question_has_extraction_language"), question),
        "question_targets_retrieval_params": _any_match(
            detection.flat_patterns_for("question_targets_retrieval_params"), question),
        "context_has_imperative_language": _any_match(
            detection.flat_patterns_for("context_has_imperative_language"), retrieved_context),
        "context_contains_pii": bool(pii_types_found),
        "pii_types_found": pii_types_found,
        "question_requests_personal_info": _any_match(
            detection.flat_patterns_for("question_requests_personal_info"), question),
        # skills/rag/external-api-abuse - the outbound query text itself,
        # not the retrieved_context (that's covered by the checks above
        # regardless of whether a chunk came from the KB or the web).
        "external_search_used": bool(external_queries),
        "external_query_targets_internal_host": _any_match(
            detection.flat_patterns_for("external_query_targets_internal_host"), external_query_text),
        "external_query_looks_like_exfiltration": _any_match(
            detection.flat_patterns_for("external_query_looks_like_exfiltration"), external_query_text),
    }


# Backwards-compatible alias - kept because a couple of tests/scripts from
# the previous round reference this name; gather_chat_evidence is the
# current name reflecting that this now covers both llm/* and rag/* skills.
gather_rag_security_evidence = gather_chat_evidence


# --- agent-to-agent evidence (skills/agents/tool-abuse, .../
# privilege-escalation) --------------------------------------------------
# "Do not automatically trust another agent" (CLAUDE.md 4.5): every field
# here comes from security_gateway/agent_registry.py's real registry, not
# from the incoming message's own claims - a message CAN'T lie its way to
# a favorable tool_in_registered_set/role_at_action_time, because neither
# is computed from anything the message provided.

def gather_agent_security_evidence(session_id: str, sender_agent_id: str, requested_tool: str,
                                    message_content: str) -> dict:
    sender = agent_registry.get_agent(sender_agent_id)
    if sender is None:
        raise ValueError(f"'{sender_agent_id}' is not a registered agent")

    session = agent_registry.session_start_role(session_id, sender_agent_id, sender["role"])
    role_change_event_id = agent_registry.role_change_event_id_since(sender_agent_id, session["first_seen_at"])

    return {
        "session_id": session_id,
        "agent_id": sender_agent_id,
        "requested_tool": requested_tool,
        "message_content": message_content[:4000],
        "agent_registered_tools": sender["allowed_tools"],
        "tool_in_registered_set": requested_tool in sender["allowed_tools"],
        "role_at_session_start": session["role_at_session_start"],
        "role_at_action_time": sender["role"],
        # security_gateway/detection.py's condition evaluator only compares
        # a field against a literal value, never one evidence field against
        # another - so the "has the role actually changed" check is
        # computed here, once, as its own boolean, rather than attempted
        # inline in detection.yaml (which cannot express a field-vs-field
        # comparison; a first draft of privilege-escalation's routing rule
        # tried exactly that and was silently always-true until this was
        # wired live and caught by a real test - see git history).
        "role_changed": session["role_at_session_start"] != sender["role"],
        "role_change_event_id": role_change_event_id,
        # A malicious A2A message (CLAUDE.md Scenario 4) is indirect-injection-
        # shaped text aimed at whichever agent receives it - reuses the same
        # skill-owned pattern registry jailbreak/rag-poisoning already check,
        # rather than a third copy of the same regex list.
        "context_has_imperative_language": _any_match(
            detection.flat_patterns_for("context_has_imperative_language"), message_content),
    }
