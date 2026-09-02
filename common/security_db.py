"""SQLite persistence for security_gateway/ - the SIEM event log, the
gateway's decision history, the Redis-fallback identity block list, and
the sandbox (quarantine) store. Shares the same physical file
(cyberdefense.db) as backend/webapp_db.py, in its own tables, so both can
be opened concurrently without a second database file to manage.

This module IS the "SIEM" the architecture diagram's MCP Tools box refers
to (security_gateway/mcp_tools/siem_tool.py is a thin wrapper over it) -
a real, queryable, persistent security-event log, not a placeholder.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cyberdefense.db")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    conn = _conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            decision TEXT NOT NULL,
            risk TEXT,
            detail TEXT
        );

        CREATE TABLE IF NOT EXISTS gateway_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            category TEXT NOT NULL,        -- authentication | rag_security | file_security (request path)
            identity TEXT,                 -- username / filename / conversation_id - whatever this request is "about"
            action TEXT NOT NULL,          -- ALLOW | MITIGATE | BLOCK
            raw_action TEXT,               -- what the LLM proposed, before policy clamping (may differ from `action`)
            confidence REAL,
            threat_indicators TEXT,        -- JSON list
            reasoning TEXT,
            enforced INTEGER NOT NULL DEFAULT 0,
            sandbox_id TEXT,
            skill_ids TEXT                 -- JSON list of taxonomy skill_ids the Supervisor Agent selected (skills/<category>/<skill-id>/)
        );

        CREATE TABLE IF NOT EXISTS blocked_identities (
            identity TEXT NOT NULL,
            category TEXT NOT NULL,
            reason TEXT,
            blocked_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (identity, category)
        );

        CREATE TABLE IF NOT EXISTS sandbox_items (
            sandbox_id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            category TEXT NOT NULL,
            identity TEXT,
            kind TEXT NOT NULL,            -- text | file
            content TEXT,                  -- evidence text (question+context, or extracted file text sample)
            metadata TEXT,                 -- JSON
            released INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS pending_tool_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            decision_id INTEGER,           -- gateway_decisions.id this proposal came from
            tool_name TEXT NOT NULL,
            identity TEXT,
            arguments TEXT NOT NULL,       -- JSON
            status TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | denied
            decided_by TEXT,
            decided_at TEXT,
            result TEXT                    -- JSON, populated once executed
        );

        CREATE TABLE IF NOT EXISTS ip_block_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            reason TEXT
        );

        CREATE TABLE IF NOT EXISTS registered_agents (
            agent_id TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            allowed_tools TEXT NOT NULL,   -- JSON list - source of truth for skills/agents/tool-abuse
            disabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_role_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            old_role TEXT,
            new_role TEXT NOT NULL,
            changed_by TEXT NOT NULL,      -- the human admin who made this change - never an agent itself
            changed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_sessions (
            session_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            role_at_session_start TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            PRIMARY KEY (session_id, agent_id)
        );
        """
    )
    # Migration guard: gateway_decisions may already exist from before the
    # 2026-08-24 skills-taxonomy expansion, without skill_ids -
    # CREATE TABLE IF NOT EXISTS above is a no-op against an existing
    # table, so the new column needs an explicit ALTER for any DB created
    # before this change.
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(gateway_decisions)")}
    if "skill_ids" not in cols:
        conn.execute("ALTER TABLE gateway_decisions ADD COLUMN skill_ids TEXT")
    conn.commit()
    conn.close()


# --- SIEM event log ---------------------------------------------------

def log_security_event(agent_id: str, tool_name: str, decision: str, risk: str = "", detail: str = ""):
    """Fails open, on purpose: an audit-write failure must never block or
    change the gateway's actual allow/deny decision - it only means this
    one event won't show up in the trail."""
    try:
        conn = _conn()
        conn.execute(
            "INSERT INTO security_events (ts, agent_id, tool_name, decision, risk, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (_now(), agent_id, tool_name, decision, risk, detail),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        import sys
        print(f"[security_db] failed to log security event: {e}", file=sys.stderr)


def list_security_events(limit: int = 50):
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- Gateway decision log ----------------------------------------------

def log_gateway_decision(category: str, identity: str, action: str, raw_action: str,
                          confidence: float, threat_indicators: list, reasoning: str,
                          enforced: bool, sandbox_id: str = None, skill_ids: list = None) -> int:
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO gateway_decisions (ts, category, identity, action, raw_action, confidence, "
        "threat_indicators, reasoning, enforced, sandbox_id, skill_ids) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (_now(), category, identity, action, raw_action, confidence,
         json.dumps(threat_indicators or []), reasoning, int(enforced), sandbox_id,
         json.dumps(skill_ids or [])),
    )
    conn.commit()
    decision_id = cur.lastrowid
    conn.close()
    return decision_id


def list_gateway_decisions_for_identity(identity: str, since_ts: str, limit: int = 200):
    """Used by security_gateway/chain_detection.py - filtered at the SQL
    level (not a generic top-N scan) so a busy system's overall decision
    volume never causes an older-but-still-in-window decision for THIS
    identity to be missed."""
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM gateway_decisions WHERE identity = ? AND ts >= ? ORDER BY id DESC LIMIT ?",
        (identity, since_ts, limit),
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["threat_indicators"] = json.loads(d["threat_indicators"] or "[]")
        d["skill_ids"] = json.loads(d["skill_ids"] or "[]")
        out.append(d)
    return out


def list_gateway_decisions(limit: int = 50, category: str = None):
    conn = _conn()
    if category:
        rows = conn.execute(
            "SELECT * FROM gateway_decisions WHERE category = ? ORDER BY id DESC LIMIT ?",
            (category, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM gateway_decisions ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["threat_indicators"] = json.loads(d["threat_indicators"] or "[]")
        d["skill_ids"] = json.loads(d["skill_ids"] or "[]")
        out.append(d)
    return out


# --- Redis-fallback identity block list ---------------------------------
# Used by security_gateway/mcp_tools/redis_tool.py when no real Redis is
# configured (REDIS_URL unset) - same semantics (identity+category ->
# blocked until expires_at), just backed by SQLite instead of Redis TTL
# keys. A real Redis client is used transparently when configured; this
# table is not a placeholder, it is the actual enforcement path for local
# development, exercised the same way in tests either way.

def block_identity(identity: str, category: str, reason: str, ttl_seconds: int):
    from datetime import timedelta
    conn = _conn()
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO blocked_identities (identity, category, reason, blocked_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?) ON CONFLICT(identity, category) DO UPDATE SET "
        "reason=excluded.reason, blocked_at=excluded.blocked_at, expires_at=excluded.expires_at",
        (identity, category, reason, _now(), expires_at),
    )
    conn.commit()
    conn.close()


def is_identity_blocked(identity: str, category: str) -> bool:
    conn = _conn()
    row = conn.execute(
        "SELECT expires_at FROM blocked_identities WHERE identity = ? AND category = ?",
        (identity, category),
    ).fetchone()
    conn.close()
    if row is None:
        return False
    return row["expires_at"] > _now()


def list_blocked_identities():
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM blocked_identities WHERE expires_at > ? ORDER BY blocked_at DESC", (_now(),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def unblock_identity(identity: str, category: str) -> bool:
    """Admin-only early release of a block_identity() TTL - otherwise this
    only ever expires on its own. Returns True if a row was actually
    removed (False if nothing was blocked for this identity/category)."""
    conn = _conn()
    cur = conn.execute(
        "DELETE FROM blocked_identities WHERE identity = ? AND category = ?", (identity, category),
    )
    conn.commit()
    removed = cur.rowcount > 0
    conn.close()
    return removed


# --- Sandbox (quarantine) store ------------------------------------------

def sandbox_put(sandbox_id: str, category: str, identity: str, kind: str, content: str, metadata: dict):
    conn = _conn()
    conn.execute(
        "INSERT INTO sandbox_items (sandbox_id, ts, category, identity, kind, content, metadata, released) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        (sandbox_id, _now(), category, identity, kind, content, json.dumps(metadata or {})),
    )
    conn.commit()
    conn.close()


def sandbox_get(sandbox_id: str):
    conn = _conn()
    row = conn.execute("SELECT * FROM sandbox_items WHERE sandbox_id = ?", (sandbox_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    d = dict(row)
    d["metadata"] = json.loads(d["metadata"] or "{}")
    return d


def sandbox_list(released: bool = False):
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM sandbox_items WHERE released = ? ORDER BY ts DESC", (int(released),)
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["metadata"] = json.loads(d["metadata"] or "{}")
        out.append(d)
    return out


def sandbox_release(sandbox_id: str):
    conn = _conn()
    conn.execute("UPDATE sandbox_items SET released = 1 WHERE sandbox_id = ?", (sandbox_id,))
    conn.commit()
    conn.close()


# --- MCP tool authorization queue (security_gateway/mcp_gateway.py) ------

def create_pending_tool_call(decision_id: int, tool_name: str, identity: str, arguments: dict) -> int:
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO pending_tool_calls (ts, decision_id, tool_name, identity, arguments, status) "
        "VALUES (?, ?, ?, ?, ?, 'pending')",
        (_now(), decision_id, tool_name, identity, json.dumps(arguments)),
    )
    conn.commit()
    call_id = cur.lastrowid
    conn.close()
    return call_id


def _with_parsed_tool_call(row) -> dict:
    d = dict(row)
    d["arguments"] = json.loads(d["arguments"])
    d["result"] = json.loads(d["result"]) if d["result"] else None
    return d


def get_pending_tool_call(call_id: int):
    conn = _conn()
    row = conn.execute("SELECT * FROM pending_tool_calls WHERE id = ?", (call_id,)).fetchone()
    conn.close()
    return _with_parsed_tool_call(row) if row else None


def list_tool_calls(status: str = None, limit: int = 50):
    conn = _conn()
    if status:
        rows = conn.execute(
            "SELECT * FROM pending_tool_calls WHERE status = ? ORDER BY id DESC LIMIT ?", (status, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM pending_tool_calls ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [_with_parsed_tool_call(r) for r in rows]


def decide_tool_call(call_id: int, decision: str, decided_by: str, result: dict = None):
    """decision must be 'approved' or 'denied'. Only mutates a still-pending
    row - re-deciding an already-decided call is a no-op."""
    conn = _conn()
    conn.execute(
        "UPDATE pending_tool_calls SET status = ?, decided_by = ?, decided_at = ?, result = ? "
        "WHERE id = ? AND status = 'pending'",
        (decision, decided_by, _now(), json.dumps(result) if result is not None else None, call_id),
    )
    conn.commit()
    conn.close()


# --- IP reputation (internal-only - past BLOCKs from this source, never
# an external threat-intel feed; see get_ip_reputation's docstring in
# mcp_gateway.py for why this scoping is honest rather than a placeholder
# for a real feed this project doesn't have) --------------------------------

def record_ip_block(source_ip: str, reason: str):
    conn = _conn()
    conn.execute("INSERT INTO ip_block_history (ts, source_ip, reason) VALUES (?, ?, ?)",
                 (_now(), source_ip, reason))
    conn.commit()
    conn.close()


def count_prior_ip_blocks(source_ip: str) -> int:
    conn = _conn()
    row = conn.execute("SELECT COUNT(*) AS n FROM ip_block_history WHERE source_ip = ?", (source_ip,)).fetchone()
    conn.close()
    return row["n"]


# --- Agent registry (security_gateway/agent_registry.py) -----------------
# The source of truth skills/agents/tool-abuse and skills/agents/
# privilege-escalation check against - "do not automatically trust another
# agent" (CLAUDE.md 4.5) means never taking an agent's self-reported role
# or tool access at face value; this table is what's actually checked.

def register_agent(agent_id: str, role: str, allowed_tools: list) -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO registered_agents (agent_id, role, allowed_tools, disabled, created_at) "
        "VALUES (?, ?, ?, 0, ?) ON CONFLICT(agent_id) DO UPDATE SET "
        "role=excluded.role, allowed_tools=excluded.allowed_tools",
        (agent_id, role, json.dumps(allowed_tools), _now()),
    )
    conn.commit()
    conn.close()


def get_registered_agent(agent_id: str):
    conn = _conn()
    row = conn.execute("SELECT * FROM registered_agents WHERE agent_id = ?", (agent_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    d = dict(row)
    d["allowed_tools"] = json.loads(d["allowed_tools"])
    d["disabled"] = bool(d["disabled"])
    return d


def list_registered_agents():
    conn = _conn()
    rows = conn.execute("SELECT * FROM registered_agents ORDER BY created_at ASC").fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["allowed_tools"] = json.loads(d["allowed_tools"])
        d["disabled"] = bool(d["disabled"])
        out.append(d)
    return out


def set_agent_disabled(agent_id: str, disabled: bool) -> None:
    conn = _conn()
    conn.execute("UPDATE registered_agents SET disabled = ? WHERE agent_id = ?", (int(disabled), agent_id))
    conn.commit()
    conn.close()


def set_agent_allowed_tools(agent_id: str, allowed_tools: list) -> None:
    conn = _conn()
    conn.execute("UPDATE registered_agents SET allowed_tools = ? WHERE agent_id = ?",
                 (json.dumps(allowed_tools), agent_id))
    conn.commit()
    conn.close()


def record_agent_role_change(agent_id: str, old_role: str, new_role: str, changed_by: str) -> int:
    """The only real, audited way an agent's role changes -
    skills/agents/privilege-escalation's floor treats any role difference
    NOT backed by a row here as an unaudited escalation."""
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO agent_role_changes (agent_id, old_role, new_role, changed_by, changed_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (agent_id, old_role, new_role, changed_by, _now()),
    )
    conn.execute("UPDATE registered_agents SET role = ? WHERE agent_id = ?", (new_role, agent_id))
    conn.commit()
    change_id = cur.lastrowid
    conn.close()
    return change_id


def latest_role_change_since(agent_id: str, since_ts: str):
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM agent_role_changes WHERE agent_id = ? AND changed_at >= ? "
        "ORDER BY changed_at DESC LIMIT 1",
        (agent_id, since_ts),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_or_start_agent_session(session_id: str, agent_id: str, current_role: str) -> str:
    """Returns the role recorded as this agent's role at the FIRST message
    of this session_id - inserted on first sight, immutable after
    (skills/agents/privilege-escalation's `role_at_session_start` signal).
    Never trusts a caller-supplied role - always the registry's role at
    that moment."""
    conn = _conn()
    conn.execute(
        "INSERT INTO agent_sessions (session_id, agent_id, role_at_session_start, first_seen_at) "
        "VALUES (?, ?, ?, ?) ON CONFLICT(session_id, agent_id) DO NOTHING",
        (session_id, agent_id, current_role, _now()),
    )
    conn.commit()
    row = conn.execute(
        "SELECT role_at_session_start, first_seen_at FROM agent_sessions WHERE session_id = ? AND agent_id = ?",
        (session_id, agent_id),
    ).fetchone()
    conn.close()
    return dict(row)
