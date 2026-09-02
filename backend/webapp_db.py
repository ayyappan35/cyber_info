"""SQLite persistence for the web app itself (accounts, conversations,
messages). Shares one physical DB file with the top-level db.py, which
models the mock login system that the red/blue cyber-range agents attack -
these are the real users of this product, not simulated attack targets, but
both modules' tables are named distinctly (app_users vs users, etc.) so they
coexist safely in the same file. db.py's reset=True path is scoped to only
drop its own tables for exactly this reason - never touch that invariant
without checking db.py's init_db() first.
"""
import os
import sqlite3
import uuid
from datetime import datetime, timezone

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_PROJECT_ROOT, "cyberdefense.db")

# agentic_system branch: main's LOCKOUT_THRESHOLD=3 fixed-count auto-lock
# is REMOVED - account locking is now driven entirely by the Security
# Gateway's own agentic BLOCK verdict (see lock_account() below). This
# constant is kept only so anything on this branch that still imports it
# (docs, stale references) fails loudly/obviously rather than silently -
# nothing in this branch's actual control flow reads it anymore.
LOCKOUT_THRESHOLD = 3


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
        CREATE TABLE IF NOT EXISTS app_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT 'New chat',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id TEXT NOT NULL,
            role TEXT NOT NULL,       -- user | assistant
            content TEXT NOT NULL,
            sources TEXT,             -- JSON-encoded list of retrieved source names, assistant only
            transcript TEXT,          -- JSON-encoded full agent trace (reasoning + every tool
                                       -- call/arguments/result) for this turn, assistant only
            ts TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            revoked_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS training_files (
            filename TEXT PRIMARY KEY,
            filesize INTEGER NOT NULL,
            trained_by TEXT NOT NULL,
            date TEXT NOT NULL
        );
        """
    )
    # CREATE TABLE IF NOT EXISTS only handles brand-new DBs - migrate an
    # already-existing messages table that predates the transcript column.
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(messages)")}
    if "transcript" not in existing_cols:
        conn.execute("ALTER TABLE messages ADD COLUMN transcript TEXT")

    # Same for app_users predating role/lockout tracking.
    user_cols = {row["name"] for row in conn.execute("PRAGMA table_info(app_users)")}
    if "role" not in user_cols:
        conn.execute("ALTER TABLE app_users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if "failed_attempts" not in user_cols:
        conn.execute("ALTER TABLE app_users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
    if "locked" not in user_cols:
        conn.execute("ALTER TABLE app_users ADD COLUMN locked INTEGER NOT NULL DEFAULT 0")
    if "email" not in user_cols:
        # SQLite can't add a UNIQUE column via ALTER TABLE on an existing
        # table, so uniqueness for pre-existing DBs is enforced in
        # create_user() instead of at the schema level here.
        conn.execute("ALTER TABLE app_users ADD COLUMN email TEXT")
    if "mfa_hold" not in user_cols:
        # Set by the require_mfa MCP tool (security_gateway/mcp_gateway.py).
        # This project has no real TOTP/email second-factor verification
        # flow - a hold is an honest, real deterministic access restriction
        # (login blocked until an admin clears it), not a fake MFA
        # challenge. See skills/authentication/*/SKILL.md's "what security
        # boundaries apply" sections.
        conn.execute("ALTER TABLE app_users ADD COLUMN mfa_hold INTEGER NOT NULL DEFAULT 0")
    if "sessions_invalidated_before" not in user_cols:
        # Set by the terminate_session MCP tool - any JWT with an `iat`
        # before this cutoff is rejected by auth.get_current_user, even if
        # its signature and per-jti revocation status are both still
        # valid. NULL means no cutoff has ever been set for this user.
        conn.execute("ALTER TABLE app_users ADD COLUMN sessions_invalidated_before TEXT")

    conn.commit()
    conn.close()


def get_user(username: str):
    conn = _conn()
    row = conn.execute("SELECT * FROM app_users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username: str, password_hash: str, email: str = None, role: str = "user"):
    conn = _conn()
    conn.execute(
        "INSERT INTO app_users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, email, password_hash, role, _now()),
    )
    conn.commit()
    conn.close()


def get_user_by_email(email: str):
    conn = _conn()
    row = conn.execute("SELECT * FROM app_users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return dict(row) if row else None


def user_count() -> int:
    conn = _conn()
    row = conn.execute("SELECT COUNT(*) AS n FROM app_users").fetchone()
    conn.close()
    return row["n"]


def list_users():
    conn = _conn()
    rows = conn.execute(
        "SELECT username, email, role, locked, mfa_hold, created_at FROM app_users ORDER BY created_at ASC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_role(username: str, role: str):
    conn = _conn()
    conn.execute("UPDATE app_users SET role = ? WHERE username = ?", (role, username))
    conn.commit()
    conn.close()


def set_mfa_hold(username: str, hold: bool):
    conn = _conn()
    conn.execute("UPDATE app_users SET mfa_hold = ? WHERE username = ?", (int(hold), username))
    conn.commit()
    conn.close()


def set_sessions_invalidated_before(username: str, cutoff_iso: str):
    conn = _conn()
    conn.execute("UPDATE app_users SET sessions_invalidated_before = ? WHERE username = ?",
                 (cutoff_iso, username))
    conn.commit()
    conn.close()


def record_failed_login(username: str):
    """agentic_system branch: increments failed_attempts as evidence only
    - does NOT auto-lock at a fixed threshold anymore (main's
    LOCKOUT_THRESHOLD=3 rule is removed on this branch). Locking the
    account is now driven entirely by the Security Gateway's own agentic
    BLOCK verdict - see lock_account() below and
    backend/routers/auth_router.py. Returns the updated failed_attempts
    count (never "locked": True from here anymore)."""
    conn = _conn()
    row = conn.execute("SELECT failed_attempts FROM app_users WHERE username = ?", (username,)).fetchone()
    if row is None:
        conn.close()
        return None
    failed = row["failed_attempts"] + 1
    conn.execute("UPDATE app_users SET failed_attempts = ? WHERE username = ?", (failed, username))
    conn.commit()
    conn.close()
    return {"failed_attempts": failed, "locked": False}


def lock_account(username: str) -> bool:
    """agentic_system branch: the ONLY way an account gets locked now -
    called from backend/routers/auth_router.py exactly when
    security_gateway/gateway.py's Security LLM verdict is BLOCK, replacing
    main's fixed "3 wrong passwords" rule with the model's own judgment
    call. Returns False if the username doesn't exist."""
    conn = _conn()
    row = conn.execute("SELECT username FROM app_users WHERE username = ?", (username,)).fetchone()
    if row is None:
        conn.close()
        return False
    conn.execute("UPDATE app_users SET locked = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return True


def reset_failed_login(username: str):
    conn = _conn()
    conn.execute(
        "UPDATE app_users SET failed_attempts = 0 WHERE username = ?", (username,)
    )
    conn.commit()
    conn.close()


def unlock_account(username: str) -> bool:
    """Admin-only: clears both `locked` and `failed_attempts`. On the
    agentic_system branch `locked` is set by lock_account() (driven by
    the Security Gateway's BLOCK verdict, not a fixed count), but
    clearing failed_attempts too still matters - it's real evidence fed
    back into the next login's evidence dict, and a fresh start is what
    "unlock" should mean either way. Nothing else in this codebase can
    ever clear a lock: auth_router.py's login only calls
    reset_failed_login() on a SUCCESSFUL login, and a locked account can
    never succeed (locked is checked before the password even is) - so
    without this, a lock is otherwise permanent. Returns False if the
    username doesn't exist."""
    conn = _conn()
    row = conn.execute("SELECT username FROM app_users WHERE username = ?", (username,)).fetchone()
    if row is None:
        conn.close()
        return False
    conn.execute(
        "UPDATE app_users SET locked = 0, failed_attempts = 0 WHERE username = ?", (username,)
    )
    conn.commit()
    conn.close()
    return True


def create_conversation(username: str, title: str = "New chat") -> str:
    conv_id = uuid.uuid4().hex[:12]
    conn = _conn()
    conn.execute(
        "INSERT INTO conversations (id, username, title, created_at) VALUES (?, ?, ?, ?)",
        (conv_id, username, title, _now()),
    )
    conn.commit()
    conn.close()
    return conv_id


def list_conversations(username: str):
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM conversations WHERE username = ? ORDER BY created_at DESC", (username,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_conversation(conv_id: str, username: str):
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM conversations WHERE id = ? AND username = ?", (conv_id, username)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def rename_conversation(conv_id: str, title: str):
    conn = _conn()
    conn.execute("UPDATE conversations SET title = ? WHERE id = ?", (title, conv_id))
    conn.commit()
    conn.close()


def delete_conversation(conv_id: str, username: str):
    conn = _conn()
    conn.execute("DELETE FROM conversations WHERE id = ? AND username = ?", (conv_id, username))
    conn.execute("DELETE FROM messages WHERE conversation_id = ?", (conv_id,))
    conn.commit()
    conn.close()


def add_message(conv_id: str, role: str, content: str, sources=None, transcript=None):
    import json
    conn = _conn()
    conn.execute(
        "INSERT INTO messages (conversation_id, role, content, sources, transcript, ts) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            conv_id, role, content,
            json.dumps(sources) if sources else None,
            json.dumps(transcript) if transcript else None,
            _now(),
        ),
    )
    conn.commit()
    conn.close()


def record_training_file(filename: str, filesize: int, trained_by: str):
    """Upsert one row per filename - reingesting the same filename updates
    its filesize/trained_by/date in place instead of adding a duplicate row."""
    conn = _conn()
    conn.execute(
        """
        INSERT INTO training_files (filename, filesize, trained_by, date)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(filename) DO UPDATE SET
            filesize = excluded.filesize,
            trained_by = excluded.trained_by,
            date = excluded.date
        """,
        (filename, filesize, trained_by, _now()),
    )
    conn.commit()
    conn.close()


def list_training_files():
    conn = _conn()
    rows = conn.execute(
        "SELECT filename, filesize, trained_by, date FROM training_files ORDER BY date DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def revoke_jti(jti: str):
    conn = _conn()
    conn.execute(
        "INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (?, ?)",
        (jti, _now()),
    )
    conn.commit()
    conn.close()


def is_jti_revoked(jti: str) -> bool:
    conn = _conn()
    row = conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone()
    conn.close()
    return row is not None


def get_messages(conv_id: str):
    import json
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM messages WHERE conversation_id = ? ORDER BY id ASC", (conv_id,)
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["sources"] = json.loads(d["sources"]) if d["sources"] else []
        d["transcript"] = json.loads(d["transcript"]) if d["transcript"] else []
        out.append(d)
    return out
