"""Security LLM node: the architecture diagram's single reasoning step,
fed by the Supervisor Agent's three inputs (security_gateway/
supervisor_agent.py) - Skills (every taxonomy skill's SKILL.md content
for this request_category, unfiltered), Knowledge (grounding retrieved
from the threat-knowledge base), and Security Context (the evidence
already gathered for this request) - and required to return a
schema-validated SecurityDecision (security_gateway/decision.py) - never
free text parsed after the fact.

No hardcoded "if attack_type == X: risk = Y" logic here (CLAUDE.md
section 8) - the model alone reasons over which skill(s) actually apply
and what the verdict is; nothing upstream pre-filters. This module's job
is only building that one prompt, calling whichever provider config.py's
LLM_PROVIDER selects with structured output enabled, and validating the
response shape. Downstream, gateway.py's Policy step (detection.py's
floor/ceiling + policy.py's clamp) is the deterministic layer this
decision can never bypass - floor/ceiling evaluate every skill offered
here unconditionally, never gated by `matched_skill_ids` below.

`SecurityDecision.matched_skill_ids` (2026-09-01) is how the Supervisor
Agent's "Select/Add Relevant Skills" behavior actually shows up in the
audit trail again: since every skill in scope is now always fed into
this prompt (no upstream filtering), `gateway.py` needs the model to
report back WHICH of them actually explain its verdict, or `skill_ids`/
the per-skill `policy.py` response.yaml override lookup would otherwise
default to a meaningless static "first skill in the category" - a real
regression this field fixes.

Two providers are actually implemented (not just declared in config.py):
- ollama (default, local): Ollama's `format: "json"` mode.
- anthropic (Claude): tool-use forcing (`tool_choice`) - the model is
  required to call a single `submit_security_decision` tool matching
  SecurityDecision's schema, which Anthropic validates server-side before
  it ever reaches this code. Switching providers is one setting
  (LLM_PROVIDER in .env) - no code change needed at the call sites
  (security_gateway/gateway.py never knows which provider answered).
openai is declared in config.py but not implemented here - would raise
NotImplementedError rather than silently falling back to Ollama.
"""
import json

import httpx
from pydantic import ValidationError

from common.config import get_settings
from security_gateway.decision import SecurityDecision
from security_gateway.mcp_gateway import TOOL_CATALOG

OLLAMA_CHAT_URL_SUFFIX = "/api/chat"

_DECISION_TOOL_SCHEMA = {
    "name": "submit_security_decision",
    "description": "Submit the security decision for this request.",
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["ALLOW", "MITIGATE", "BLOCK"]},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "threat_indicators": {"type": "array", "items": {"type": "string"}},
            "reasoning": {"type": "string"},
            "required_tools": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "arguments": {"type": "object"},
                    },
                    "required": ["name"],
                },
            },
            "matched_skill_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["action", "confidence", "reasoning"],
    },
}


class DiscussionFailed(Exception):
    """Raised when the model never produces a schema-valid decision within
    the retry budget - gateway.py treats this as a hard fail-closed
    trigger, never as an implicit ALLOW."""


def _build_prompt(category: str, skills: list, evidence: dict, retrieved_knowledge: list,
                   available_tools: list) -> tuple:
    """Returns (system_text, user_text) - kept as a plain pair rather than
    a provider-specific messages list, since Ollama and Anthropic structure
    the system prompt differently (Ollama: a role:"system" message in the
    same list; Anthropic: a separate top-level `system` parameter).

    `skills` is the Supervisor Agent's Skills input - EVERY skill in this
    request_category's taxonomy scope (supervisor_agent.py::all_skills_for()),
    unfiltered; deciding which of them actually apply is this call's own
    job, not something done upstream."""
    knowledge_block = "\n\n".join(
        f"- ({k['source']}) {k['content'][:500]}" for k in retrieved_knowledge
    ) or "(no relevant threat knowledge retrieved)"

    skills_block = "\n\n".join(
        f"## Skill: {s['skill_id']} (taxonomy category: {s['category']})\n{s['content']}" for s in skills
    )
    skill_names = ", ".join(s["skill_id"] for s in skills)
    tools_block = "\n".join(
        f"- {name}: call with arguments {json.dumps(TOOL_CATALOG[name].get('args_hint', {}))}"
        for name in available_tools
    ) or "(none available for this category)"

    system = (
        "You are the Security LLM node of an AI cyber-defense gateway. "
        "You will be given every security skill's methodology registered for this request's category "
        "(decide for yourself which, if any, genuinely apply - do not assume all of them do), live "
        "evidence about one request (the Security Context), and grounding knowledge retrieved from a "
        "threat-intelligence knowledge base. Reason about whether this request is malicious under ANY "
        "of the given skills, then respond with ONLY a JSON object matching exactly this shape, no "
        "other text:\n"
        '{"action": "ALLOW"|"MITIGATE"|"BLOCK", "confidence": 0.0-1.0, '
        '"threat_indicators": ["short phrase", ...], "reasoning": "1-2 short sentences, plain language", '
        '"required_tools": [{"name": "tool_name", "arguments": {...}}, ...], '
        '"matched_skill_ids": ["skill_id", ...]}\n\n'
        "ALLOW = no real threat signal under any skill. MITIGATE = suspicious but not severe/certain "
        "enough to fully deny. BLOCK = clear, high-confidence malicious pattern under at least one "
        "skill. Base your action and confidence only on the evidence and skill guidance given - do "
        "not invent evidence not present below.\n\n"
        "reasoning: this is shown directly to end users, so keep it to at most 2 short, plain-language "
        "sentences - state the threat pattern and the reason, nothing else. Never mention internal file "
        "names, document names, skill IDs, function names, or system-implementation details, even if "
        "they appear in the evidence or retrieved knowledge below; describe what those sources say, "
        "never what they are called.\n\n"
        f"required_tools: propose ZERO OR MORE tool calls from this exact list, each with a `name` and "
        f"the `arguments` object that tool needs (use the values already present in the evidence/"
        f"context above for things like username/source_ip/document_id - never invent a value that "
        f"isn't grounded in the evidence given to you), only if this specific request genuinely calls "
        f"for that remediation/investigation step:\n{tools_block}\nAn ALLOW decision should normally "
        "propose no tools. Never propose a tool not in this list, and never omit a `name`.\n\n"
        f"matched_skill_ids: from this exact list of skill_ids you were given - {skill_names} - name "
        f"ONLY the ones that specifically explain your action/reasoning for THIS request, the ones a "
        f"human reviewer would point to as 'this is why'. Most requests genuinely match at most one or "
        f"two of the skills given to you, not all of them - do not list a skill just because its "
        f"methodology was included above. Leave empty only for a genuinely clean ALLOW with nothing "
        f"specific to point to. Never list a skill_id not in that exact list."
    )
    user = (
        f"## Skills registered for this request's category: {skill_names} (request category: {category})\n\n"
        f"{skills_block}\n\n"
        f"## Evidence for this request (Security Context)\n{json.dumps(evidence, indent=2, default=str)}\n\n"
        f"## Retrieved threat knowledge\n{knowledge_block}\n\n"
        "Respond with the JSON object now."
    )
    return system, user


async def _discuss_ollama(system: str, user: str, model: str, max_retries: int, log) -> SecurityDecision:
    settings = get_settings()
    url = settings.ollama_base_url.rstrip("/") + OLLAMA_CHAT_URL_SUFFIX
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

    last_error = None
    async with httpx.AsyncClient(timeout=120) as client:
        for attempt in range(1, max_retries + 2):
            try:
                resp = await client.post(url, json={
                    "model": model, "messages": messages, "format": "json",
                    "stream": False, "options": {"temperature": 0.1},
                })
                resp.raise_for_status()
                content = resp.json()["message"]["content"]
                decision = SecurityDecision(**json.loads(content))
                log(f"  [llm_discussion:ollama] model={model} action={decision.action} "
                    f"confidence={decision.confidence:.2f}")
                return decision
            except (httpx.HTTPError, json.JSONDecodeError, ValidationError, KeyError) as e:
                last_error = e
                log(f"  [llm_discussion:ollama] attempt {attempt} failed: {e}")
                messages.append({
                    "role": "user",
                    "content": "That was not valid JSON matching the required shape. "
                               "Respond with ONLY the JSON object, nothing else.",
                })

    raise DiscussionFailed(f"No schema-valid decision after {max_retries + 1} attempts: {last_error}")


async def _discuss_anthropic(system: str, user: str, model: str, max_retries: int, log) -> SecurityDecision:
    from anthropic import AsyncAnthropic

    settings = get_settings()
    if not settings.anthropic_api_key:
        raise DiscussionFailed("ANTHROPIC_API_KEY is not set - see .env.example")

    client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    messages = [{"role": "user", "content": user}]

    last_error = None
    for attempt in range(1, max_retries + 2):
        try:
            resp = await client.messages.create(
                model=model, max_tokens=1024, system=system, messages=messages,
                tools=[_DECISION_TOOL_SCHEMA],
                tool_choice={"type": "tool", "name": "submit_security_decision"},
            )
            tool_use = next((b for b in resp.content if b.type == "tool_use"), None)
            if tool_use is None:
                raise ValueError("no tool_use block in Claude's response")
            decision = SecurityDecision(**tool_use.input)
            log(f"  [llm_discussion:anthropic] model={model} action={decision.action} "
                f"confidence={decision.confidence:.2f}")
            return decision
        except (ValidationError, ValueError, KeyError) as e:
            last_error = e
            log(f"  [llm_discussion:anthropic] attempt {attempt} failed: {e}")
        except Exception as e:  # anthropic SDK's own API/connection errors
            last_error = e
            log(f"  [llm_discussion:anthropic] attempt {attempt} request failed: {e}")

    raise DiscussionFailed(f"No schema-valid decision after {max_retries + 1} attempts: {last_error}")


async def discuss(category: str, skills: list, evidence: dict, retrieved_knowledge: list,
                   available_tools: list = None, model: str = None, max_retries: int = 2,
                   log=print) -> SecurityDecision:
    from security_gateway import runtime_config
    provider = runtime_config.get_active_provider()
    model = model or runtime_config.get_active_model()
    system, user = _build_prompt(category, skills, evidence, retrieved_knowledge, available_tools or [])

    if provider == "ollama":
        return await _discuss_ollama(system, user, model, max_retries, log)
    if provider == "anthropic":
        return await _discuss_anthropic(system, user, model, max_retries, log)
    raise NotImplementedError(f"LLM_PROVIDER='{provider}' has no Security LLM Discussion implementation "
                               f"(only 'ollama' and 'anthropic' are wired up)")
