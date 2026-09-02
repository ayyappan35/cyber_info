"""The chat 'query' endpoint: an agentic run (backend/pipelines/
chat_agent.py - the LLM calls real tools across multiple turns, grounded
in the skill system) followed by the RAG Security gateway check. Every
question is checked live against both the question itself and everything
the agent actually retrieved before its answer is allowed to reach
anyone - see chat_agent.py's docstring for why the check runs AFTER the
agent's tool-use loop rather than before a single fixed retrieval.

Two endpoints share the same flow:
- POST ""        blocking, returns the full result at once.
- POST "/stream" Server-Sent Events - live "thinking / tool_call /
  reasoning" progress, not just a static spinner. This is what the web
  chat UI uses.
"""
import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

import auth
import webapp_db as db
from pipelines.chat_agent import run_chat_agent
from schemas import QueryRequest, QueryResponse
from security_gateway import gateway

router = APIRouter(prefix="/api/query", tags=["query"])

def _security_steps(route_step: dict, discussion_step: dict) -> list:
    return [
        {"role": "tool_call", "name": "supervisor_agent.route", "arguments": route_step["arguments"],
         "result": route_step["result"]},
        {"role": "tool_call", "name": "security_llm_discussion", "arguments": discussion_step["arguments"],
         "result": discussion_step["result"]},
    ]


async def _run(request: Request, username: str, question: str, on_event=None) -> dict:
    async def emit(event: dict):
        if on_event:
            await on_event(event)

    user = db.get_user(username)
    requester_role = user["role"] if user else "user"
    agent_result = await run_chat_agent(question, requester_username=username, requester_role=requester_role,
                                         log=request.app.state.log, on_event=on_event)

    evidence = gateway.gather_chat_evidence(question, agent_result["context"], agent_result["sources"],
                                             external_queries=agent_result.get("external_queries"))
    await emit({"type": "reasoning", "content": "Running RAG/LLM Security gateway check..."})
    result = await gateway.analyze(
        "rag_security", identity=username, evidence=evidence,
        sandbox_payload={"kind": "text", "content": f"Q: {question}\n\nContext:\n{agent_result['context']}"},
        log=request.app.state.log,
    )
    route_step = {"arguments": {"question": question}, "result": {"skills_selected": result.skill_ids}}
    discussion_step = {
        "arguments": {"question": question, "sources": agent_result["sources"]},
        "result": {"action": result.action, "confidence": round(result.confidence, 2),
                    "threat_indicators": result.threat_indicators, "reasoning": result.reasoning},
    }
    await emit({"type": "tool_call", "name": "security_llm_discussion", **discussion_step})

    if result.action == "BLOCK":
        # The agent's own tool-call transcript is discarded here, not just
        # its answer - a search_knowledge_base RESULT could itself contain
        # the flagged content, and that must never reach the user via
        # "Show agent trace" even though the final text answer is already
        # being withheld.
        pending_call_id = next(
            (t.call_id for t in result.tool_results
             if t.tool_name == "disclose_pii_answer" and t.status == "pending_approval"),
            None,
        )
        return {"answer": result.reasoning, "sources": [],
                "transcript": _security_steps(route_step, discussion_step),
                "gateway_action": "BLOCK", "pending_call_id": pending_call_id}

    transcript = agent_result["transcript"] + _security_steps(route_step, discussion_step)
    return {"answer": agent_result["answer"], "sources": agent_result["sources"], "transcript": transcript,
            "gateway_action": result.action}


def _prepare_conversation(body: QueryRequest, username: str) -> str:
    conv_id = body.conversation_id
    if conv_id is None:
        title = body.message.strip()[:60]
        conv_id = db.create_conversation(username, title=title or "New chat")
    elif db.get_conversation(conv_id, username) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation not found")
    # Persisted even if the gateway later blocks it - the audit trail
    # should show what was sent, not just what was acted on.
    db.add_message(conv_id, "user", body.message)
    return conv_id


@router.post("", response_model=QueryResponse)
async def query(body: QueryRequest, request: Request, username: str = Depends(auth.get_current_user)):
    if not body.message.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "message must not be empty")

    conv_id = _prepare_conversation(body, username)
    payload = await _run(request, username, body.message)
    db.add_message(conv_id, "assistant", payload["answer"], sources=payload["sources"],
                    transcript=payload["transcript"])
    return QueryResponse(conversation_id=conv_id, answer=payload["answer"], sources=payload["sources"],
                          transcript=payload["transcript"])


@router.post("/stream")
async def query_stream(body: QueryRequest, request: Request, username: str = Depends(auth.get_current_user)):
    if not body.message.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "message must not be empty")

    conv_id = _prepare_conversation(body, username)
    queue: asyncio.Queue = asyncio.Queue()

    async def on_event(event: dict):
        await queue.put(event)

    async def run_and_finish():
        try:
            payload = await _run(request, username, body.message, on_event=on_event)
            db.add_message(conv_id, "assistant", payload["answer"], sources=payload["sources"],
                            transcript=payload["transcript"])
            await queue.put({"type": "done", "conversation_id": conv_id, **payload})
        except Exception as e:
            await queue.put({"type": "error", "message": str(e)})
        finally:
            await queue.put(None)

    asyncio.create_task(run_and_finish())

    async def event_stream():
        while True:
            event = await queue.get()
            if event is None:
                break
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
