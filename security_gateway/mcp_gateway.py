"""MCP Tool Authorization Gateway: the boundary between "the Security LLM
Discussion node proposed this tool call" and "this tool actually executes."

    Security LLM Discussion
            |
      required_tools: [ToolCall(name, arguments), ...]   (see decision.py)
            |
            v
    mcp_gateway.authorize_and_execute()   <- THIS MODULE
            |
      1. tool exists in TOOL_CATALOG?
      2. execute the tool's real implementation with the LLM-supplied
         arguments now (any KeyError/TypeError/ValueError the executor
         raises over a missing/malformed argument is caught here and
         denied, never allowed to crash the request)
            |
            v
      logged to SIEM either way

agentic_system branch, 2026-09-02: arguments are now taken directly from
the Security LLM's own ToolCall.arguments (security_gateway/decision.py) -
the deterministic per-tool-name argument builder that used to live here
(`_args_for()`, keyed on tool_name, pulling values only from the current
request's own trusted evidence/identity) has been removed entirely. This
is a further, deliberate regression from main's original design in the
same spirit as the category-scoping/rate-limit/approval-gate removal
below: the LLM proposing WHICH tool applies AND what arguments it takes
is fully trusted, with no independent grounding check that an argument
(a source_ip, a username, a document_id) actually belongs to this
request. A prompt-injected message can now steer block_ip/terminate_session/
disclose_pii_answer/etc. at an attacker-chosen target, not just the
current request's own identity/evidence - see docs/AGENTIC_SYSTEM_EXPERIMENT.md.

The handful of tool calls that are NOT LLM-proposed (skills/rag/
pii-exposure's forced disclose_pii_answer approval queue in gateway.py,
the agent-to-agent get_ip_reputation call in backend/routers/
agent_router.py, chat_agent.py's search_external_web) still build their
own small, local arguments dict inline at their own call site, from
their own already-known evidence - there is no longer one central
dispatch table doing this for every tool by name.

Each TOOL_CATALOG entry's `args_hint` documents the argument shape its
executor expects, purely so the Security LLM's prompt (llm_discussion.py)
can tell the model what to supply - it is documentation for the prompt,
not a validated schema; nothing here enforces that an LLM-supplied
`arguments` dict actually matches its hint."""
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from common import security_db
import webapp_db as db
from security_gateway.mcp_tools import redis_tool, sandbox_tool, siem_tool

# --- tool catalog -----------------------------------------------------------
# Every tool the Security LLM Discussion node may propose. `allowed_categories`/
# `requires_approval`/`rate_limit` are inert metadata as of the agentic_system
# merge (authorize_and_execute() below no longer reads them - see its own
# docstring); kept in place as documentation of main's original design
# rather than deleted, same treatment detection.yaml's `routing:` sections
# got. `args_hint` is live: llm_discussion.py reads it to tell the Security
# LLM what argument keys each tool's real executor expects.
TOOL_CATALOG = {
    "get_login_attempts": {
        "risk": "low", "requires_approval": False, "allowed_categories": ["authentication"],
        "args_hint": {"username": "string"},
    },
    "get_ip_reputation": {
        # "agent_security" added 2026-08-24: the one tool deliberately made
        # reachable via the agent-to-agent message path
        # (backend/routers/agent_router.py) - a narrow, low-risk, read-only
        # lookup, chosen specifically so the A2A demo can show a
        # LEGITIMATE request actually succeed, not just illegitimate ones
        # being blocked. High-risk tools (block_ip, terminate_session,
        # remove_vector, ...) deliberately do NOT get "agent_security"
        # added here - even an agent registered with one of those in its
        # own allowed_tools (agent_registry.py's ops_admin_agent seed is
        # exactly that, on purpose) still can't get it to execute via this
        # path, because this catalog never granted it. That's the direct,
        # structural answer to "can a manipulated agent trick another
        # agent into executing a high-privilege tool it lacks access to":
        # no - not even a fully-authorized agent identity can reach a tool
        # this catalog didn't scope to agent_security, regardless of what
        # its own registered role/tools claim.
        "risk": "low", "requires_approval": False, "allowed_categories": ["authentication", "agent_security"],
        "args_hint": {"source_ip": "string"},
    },
    "rate_limit_user": {
        "risk": "medium", "requires_approval": False, "allowed_categories": ["authentication"],
        "rate_limit": {"max": 20, "window_seconds": 60},
        "args_hint": {"username": "string"},
    },
    "require_mfa": {
        "risk": "high", "requires_approval": False, "allowed_categories": ["authentication"],
        "args_hint": {"username": "string"},
    },
    "block_ip": {
        "risk": "critical", "requires_approval": True, "allowed_categories": ["authentication"],
        "args_hint": {"source_ip": "string"},
    },
    "terminate_session": {
        "risk": "critical", "requires_approval": True, "allowed_categories": ["authentication"],
        "args_hint": {"username": "string"},
    },
    "get_document_provenance": {
        "risk": "low", "requires_approval": False, "allowed_categories": ["file_security", "rag_security"],
        "args_hint": {"filename": "string"},
    },
    "quarantine_document": {
        "risk": "medium", "requires_approval": False, "allowed_categories": ["file_security", "rag_security"],
        "args_hint": {"filename": "string"},
    },
    "remove_vector": {
        "risk": "high", "requires_approval": True, "allowed_categories": ["file_security", "rag_security"],
        "args_hint": {"document_id": "string"},
    },
    "disclose_pii_answer": {
        # Not LLM-proposed like the other tools - security_gateway/gateway.py
        # auto-queues this deterministically whenever skills/rag/pii-exposure's
        # floor forces BLOCK (see that skill's response.yaml, effect=
        # "tool_approval_required"). risk=critical, requires_approval=True:
        # the generated answer is computed only once an admin explicitly
        # approves, never before.
        "risk": "critical", "requires_approval": True, "allowed_categories": ["rag_security"],
        "args_hint": {"question": "string", "context": "string", "pii_types_found": "list of strings"},
    },
    "search_external_web": {
        # Also not LLM-proposed via the Security LLM Discussion node like
        # block_ip/quarantine_document are - backend/pipelines/chat_agent.py
        # calls this directly, mid-conversation, the same way it calls
        # search_knowledge_base, but routed through authorize_and_execute()
        # (unlike search_knowledge_base/get_skill_methodology, which are
        # plain local reads) because this is the one tool that leaves the
        # local network at all - CLAUDE.md's "External API Abuse"/"Data
        # exfiltration" threats apply here, not to a local ChromaDB query.
        # requires_approval=False (a read-only web lookup, not a
        # state-changing action) but rate-limited, audit-logged, and its
        # executor below refuses any query naming a private/internal host
        # before the request ever goes out - see skills/rag/
        # external-api-abuse/SKILL.md.
        "risk": "medium", "requires_approval": False, "allowed_categories": ["rag_security"],
        "rate_limit": {"max": 8, "window_seconds": 300},
        "args_hint": {"query": "string"},
    },
    "revoke_agent_credentials": {
        # skills/agents/tool-abuse's and .../privilege-escalation's own
        # SKILL.md named this exact tool as what would be needed to act on
        # a violation - the Security LLM Discussion can propose it once
        # request_category="agent_security" surfaces it via
        # tools_for_category(). critical/requires_approval: disabling an
        # agent identity outright is consequential, same tier as
        # block_ip/terminate_session.
        "risk": "critical", "requires_approval": True, "allowed_categories": ["agent_security"],
        "args_hint": {"agent_id": "string"},
    },
    "remove_agent_tool_access": {
        # A narrower containment than revoke_agent_credentials - removes
        # one tool from an agent's registered set rather than disabling it
        # outright.
        "risk": "high", "requires_approval": True, "allowed_categories": ["agent_security"],
        "args_hint": {"agent_id": "string", "tool_name": "string (the OFFENDING tool being removed)"},
    },
}

# Tools deliberately NOT implemented, and why (never faked - CLAUDE.md
# Rule 3): get_device_risk/device fingerprinting - no device_id capture
# anywhere in this app's login flow. invalidate_cache - no query/response
# cache layer exists to invalidate. rebuild_embeddings (as "re-embed
# everything with a new model") - out of scope; the real, scoped-down
# equivalent that exists is re-uploading a released sandbox item, which
# routes back through the normal file_security gateway check like any
# upload, not a special MCP tool.


@dataclass
class ToolResult:
    tool_name: str
    status: str  # authorized_executed | pending_approval | denied_out_of_scope | denied_rate_limited | denied_invalid_arguments
    arguments: dict = field(default_factory=dict)
    result: Optional[dict] = None
    call_id: Optional[int] = None
    reason: str = ""


# --- rate limiting (per tool+identity, same in-process pattern as
# security_gateway/mcp_tools/redis_tool.py's authentication attempt
# tracking) ------------------------------------------------------------

_tool_calls = defaultdict(deque)


def _rate_limited(tool_name: str, identity: str) -> bool:
    cfg = TOOL_CATALOG[tool_name].get("rate_limit")
    if cfg is None:
        return False
    key = f"{tool_name}:{identity}"
    now = time.time()
    dq = _tool_calls[key]
    while dq and now - dq[0] > cfg["window_seconds"]:
        dq.popleft()
    if len(dq) >= cfg["max"]:
        return True
    dq.append(now)
    return False


# --- real tool implementations ----------------------------------------------

def _exec_get_login_attempts(args: dict) -> dict:
    username = args["username"]
    return {
        "recent_attempt_count_1min": redis_tool.get_attempt_count(username),
        "already_blocked": redis_tool.is_blocked(username, "authentication"),
    }


def _exec_get_ip_reputation(args: dict) -> dict:
    """Internal-only reputation: how many times THIS system has previously
    BLOCKed something from this source IP. Never an external threat-intel
    feed - this project has no such data source, and fabricating one would
    violate CLAUDE.md's no-fake-implementations rule."""
    source_ip = args["source_ip"]
    return {"source_ip": source_ip, "prior_blocks_from_this_ip": security_db.count_prior_ip_blocks(source_ip),
            "scope": "internal-history-only, not external threat intelligence"}


def _exec_rate_limit_user(args: dict) -> dict:
    username = args["username"]
    redis_tool.block_identity(username, "rate_limited", "rate_limit_user MCP tool", ttl_seconds=300)
    return {"username": username, "rate_limited_for_seconds": 300}


def _exec_require_mfa(args: dict) -> dict:
    username = args["username"]
    db.set_mfa_hold(username, True)
    return {"username": username, "mfa_hold": True,
            "note": "admin-clearable access hold - no real second-factor challenge exists in this build"}


def _exec_block_ip(args: dict) -> dict:
    source_ip = args["source_ip"]
    redis_tool.block_identity(source_ip, "ip_block", "block_ip MCP tool", ttl_seconds=1800)
    security_db.record_ip_block(source_ip, "block_ip MCP tool")
    return {"source_ip": source_ip, "blocked_for_seconds": 1800}


def _exec_terminate_session(args: dict) -> dict:
    username = args["username"]
    cutoff = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db.set_sessions_invalidated_before(username, cutoff)
    return {"username": username, "sessions_invalidated_before": cutoff}


def _exec_get_document_provenance(args: dict) -> dict:
    filename = args.get("filename")
    rows = db.list_training_files()
    for r in rows:
        if r["filename"] == filename:
            return {"filename": filename, "trained_by": r["trained_by"], "date": r["date"],
                     "filesize": r["filesize"]}
    return {"filename": filename, "found": False}


def _exec_quarantine_document(args: dict) -> dict:
    # Idempotent with the automatic MITIGATE/BLOCK sandbox effect - this
    # tool exists so the LLM discussion can explicitly propose quarantine
    # as part of its reasoning even on an ALLOW-leaning call where the
    # policy-driven sandbox_payload effect wouldn't otherwise fire.
    filename = args.get("filename") or "unknown"
    sandbox_id = sandbox_tool.quarantine_text("file_security", filename,
                                                f"Explicit quarantine_document tool call for {filename}",
                                                metadata={"source": "mcp_gateway.quarantine_document"})
    return {"sandbox_id": sandbox_id}


def _exec_remove_vector(args: dict) -> dict:
    document_id = args.get("document_id")
    if not document_id:
        return {"removed": False, "reason": "no document_id in evidence"}
    import os
    import sys
    _pipelines_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend", "pipelines")
    if _pipelines_dir not in sys.path:
        sys.path.insert(0, _pipelines_dir)
    from rag_search import get_vectorstore
    vectorstore = get_vectorstore()
    vectorstore._collection.delete(where={"document_id": document_id})
    return {"removed": True, "document_id": document_id}


def _exec_disclose_pii_answer(args: dict) -> dict:
    """agentic_system branch: called directly from authorize_and_execute()
    now, same as every other tool - the requires_approval gate that used
    to mean this only ran after an admin clicked Approve is gone. On
    `main`, this is only ever called from execute_approved_call()."""
    import os
    import sys
    _pipelines_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend", "pipelines")
    if _pipelines_dir not in sys.path:
        sys.path.insert(0, _pipelines_dir)
    from rag_graph_chroma import answer as generate_answer

    question = args.get("question", "")
    context = args.get("context", "")
    generated = generate_answer(question, context) if question and context else "(missing question/context)"
    return {"question": question, "answer": generated, "pii_types_found": args.get("pii_types_found", [])}


def _exec_search_external_web(args: dict) -> dict:
    """Real DuckDuckGo Instant Answer API call - no key required, matches
    what the user asked for by name. The one executor in this catalog that
    makes an outbound network request, so it gets an SSRF guard BEFORE
    that request happens: a query naming a private/internal host or IP is
    refused here, not merely flagged afterward by skills/rag/
    external-api-abuse's floor (that floor is a second, independent
    layer covering the surrounding chat response, not a substitute for
    this pre-call check)."""
    query = (args.get("query") or "").strip()
    if not query:
        return {"error": "empty query"}

    from security_gateway import detection
    ssrf_patterns = detection.flat_patterns_for("external_query_targets_internal_host")
    if any(p.search(query) for p in ssrf_patterns):
        return {"error": "blocked: query appears to target a private/internal network location, "
                          "not a legitimate external lookup"}

    import httpx
    try:
        resp = httpx.get("https://api.duckduckgo.com/", params={
            "q": query, "format": "json", "no_html": "1", "skip_disambig": "1",
        }, timeout=8, headers={"User-Agent": "cyber-defense-agent/1.0"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"error": f"external search failed: {e}"}

    related = [
        {"text": t.get("Text", ""), "url": t.get("FirstURL", "")}
        for t in data.get("RelatedTopics", []) if isinstance(t, dict) and t.get("Text")
    ][:5]
    return {
        "query": query,
        "abstract": data.get("AbstractText", ""),
        "abstract_source": data.get("AbstractSource", ""),
        "abstract_url": data.get("AbstractURL", ""),
        "related_topics": related,
    }


def _exec_revoke_agent_credentials(args: dict) -> dict:
    from security_gateway import agent_registry
    agent_id = args.get("agent_id", "")
    agent_registry.disable_agent(agent_id)
    agent = agent_registry.get_agent(agent_id)
    return {"agent_id": agent_id, "disabled": agent["disabled"] if agent else None}


def _exec_remove_agent_tool_access(args: dict) -> dict:
    from security_gateway import agent_registry
    agent_id = args.get("agent_id", "")
    offending_tool = args.get("tool_name", "")
    agent = agent_registry.remove_tool_access(agent_id, offending_tool)
    return {"agent_id": agent_id, "removed_tool": offending_tool,
            "allowed_tools_now": agent["allowed_tools"] if agent else []}


_EXECUTORS = {
    "get_login_attempts": _exec_get_login_attempts,
    "get_ip_reputation": _exec_get_ip_reputation,
    "rate_limit_user": _exec_rate_limit_user,
    "require_mfa": _exec_require_mfa,
    "block_ip": _exec_block_ip,
    "terminate_session": _exec_terminate_session,
    "get_document_provenance": _exec_get_document_provenance,
    "quarantine_document": _exec_quarantine_document,
    "remove_vector": _exec_remove_vector,
    "disclose_pii_answer": _exec_disclose_pii_answer,
    "search_external_web": _exec_search_external_web,
    "revoke_agent_credentials": _exec_revoke_agent_credentials,
    "remove_agent_tool_access": _exec_remove_agent_tool_access,
}


def tools_for_category(request_category: str) -> list:
    """agentic_system branch: category scoping removed - every request
    category is offered the FULL tool catalog, not just the tools
    declared relevant to it on main. The Security LLM alone decides
    which tool (if any) fits, with no deterministic scope boundary."""
    return list(TOOL_CATALOG.keys())


def authorize_and_execute(tool_name: str, request_category: str, identity: str, arguments: dict,
                           decision_id: Optional[int] = None) -> ToolResult:
    """agentic_system branch (2026-09-02, extended to cover arguments too):
    category scoping, rate limiting, and the critical-risk human-approval
    gate are REMOVED - any tool the Security LLM names, with whatever
    arguments it supplied, executes immediately, regardless of category or
    declared risk tier. Only two structural checks remain, neither a
    security judgment: (1) does an executor function exist for this name,
    and (2) does the executor accept the arguments it was given (a
    KeyError/TypeError/ValueError from a missing or malformed argument is
    caught and denied here, never left to crash the request). This is a
    DELIBERATE, documented regression from main's original design - see
    docs/AGENTIC_SYSTEM_EXPERIMENT.md. It means a prompt-injected message
    that gets the model to propose block_ip/terminate_session/
    remove_vector/disclose_pii_answer now auto-executes it, with
    attacker-chosen arguments, and no human in the loop."""
    cfg = TOOL_CATALOG.get(tool_name)
    if cfg is None:
        siem_tool.log_event(agent_id="mcp_gateway", tool_name=tool_name, decision="DENIED_UNKNOWN_TOOL",
                             detail=f"proposed by request_category={request_category}")
        return ToolResult(tool_name=tool_name, status="denied_out_of_scope", reason="unknown tool")

    try:
        result = _EXECUTORS[tool_name](arguments)
    except (KeyError, TypeError, ValueError) as e:
        siem_tool.log_event(agent_id="mcp_gateway", tool_name=tool_name, decision="DENIED_INVALID_ARGUMENTS",
                             detail=f"identity={identity} arguments={arguments} error={e}")
        return ToolResult(tool_name=tool_name, status="denied_invalid_arguments", arguments=arguments,
                           reason=f"arguments did not match what this tool expects: {e}")

    siem_tool.log_event(agent_id="mcp_gateway", tool_name=tool_name, decision="AUTHORIZED_EXECUTED",
                         detail=f"identity={identity} arguments={arguments} result={result} "
                                f"[agentic_system: no category/rate-limit/approval gate applied]")
    return ToolResult(tool_name=tool_name, status="authorized_executed", arguments=arguments, result=result)


def execute_approved_call(call_id: int, decided_by: str) -> dict:
    """Called by the admin approval endpoint after a human approves a
    pending_tool_calls row - the actual execution happens here, at the
    moment of human approval, not at proposal time."""
    call = security_db.get_pending_tool_call(call_id)
    if call is None or call["status"] != "pending":
        raise ValueError(f"No pending tool call with id={call_id}")

    result = _EXECUTORS[call["tool_name"]](call["arguments"])
    security_db.decide_tool_call(call_id, "approved", decided_by, result=result)
    siem_tool.log_event(agent_id=decided_by, tool_name=call["tool_name"], decision="approved",
                         detail=f"call_id={call_id} result={result}")
    return result


def deny_call(call_id: int, decided_by: str) -> None:
    call = security_db.get_pending_tool_call(call_id)
    if call is None or call["status"] != "pending":
        raise ValueError(f"No pending tool call with id={call_id}")
    security_db.decide_tool_call(call_id, "denied", decided_by)
    siem_tool.log_event(agent_id=decided_by, tool_name=call["tool_name"], decision="denied",
                         detail=f"call_id={call_id}")
