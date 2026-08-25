# Security Gateway Tool Policy

Every agent's tool calls pass through `SecurityGateway` before they execute. Each tool has a fixed, auditable policy entry (`tool_name -> {risk, decision}`); anything without an explicit entry defaults to `{"risk": "LOW", "decision": "ALLOW"}`.

## HITL_REQUIRED (needs human approval before it executes)
- `lock_account` — permanently locks a user account. HIGH risk: no self-expiry, affects one account indefinitely.
- `unlock_account` — reverses a lock. HIGH risk: an incorrect unlock re-opens an account that may still be under active attack.
- `block_ip` — blocks all login attempts from a source IP. HIGH risk: bigger blast radius than an account-level action, since a single IP can be shared by multiple legitimate users (NAT, VPN, office network) — blocking it can lock out accounts that were never targeted.

A `HITL_REQUIRED` call is **never executed** for that turn. It is queued as a `pending_approvals` row and denied for the agent that requested it; only an admin approving it (Control Panel → Approvals) causes the actual action to run, executed directly by trusted backend code rather than replayed through the agent's tool call.

## ALLOW (executes immediately, no approval needed)
- `temporary_lock_account` — self-expiring, bounded-duration lock. The intended default response to a clear brute-force lockout-threshold breach: fast containment without waiting on a human, but with an automatic recovery path if the call turns out to be wrong.
- `create_incident` — writes an audit/incident record. Non-destructive by nature; recording that something happened carries no risk of blocking a legitimate user.
- Every read-only lookup tool (`query_auth_logs`/`get_login_history`, `geoip_lookup`/`get_ip_reputation`, `get_user_risk`, `get_incidents`, `get_agent_activity`, `get_security_policy`, `search_knowledge_base`, `answer_question`) — these only read state, so there is nothing for a human to approve.

## Why this table is static, not model-scored
The policy decision — is this specific tool allowed to run without a human — is deliberately a fixed, human-authored table rather than something an LLM scores at runtime. This keeps the actual authorization boundary auditable and predictable even when an agent's own reasoning about a *situation* (is this login attempt an attack?) is dynamic and LLM-driven. Situational risk assessment and tool-call authorization are two separate questions, answered by two separate mechanisms.
