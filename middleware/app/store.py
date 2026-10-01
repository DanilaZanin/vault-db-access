"""SQLite grant store: staged operations + audit log. Never holds passwords or tokens
(except the portal's own server-side sessions, which hold the admin's own Vault login token)."""

import json
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    db_type TEXT NOT NULL,
    scope TEXT NOT NULL,
    tables TEXT NOT NULL,
    commands TEXT NOT NULL,
    requested_for TEXT NOT NULL,
    issued_by TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL,
    username TEXT,
    lease_id TEXT,
    token_accessor TEXT,
    last_error TEXT,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS grants_status ON grants(status);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    request_id TEXT,
    grant_id TEXT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf TEXT NOT NULL,
    vault_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_check REAL NOT NULL
);
"""

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


def init(path: str | None = None) -> None:
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = sqlite3.connect(path or config.DB_PATH, check_same_thread=False, isolation_level=None)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=FULL")
        _conn.execute("PRAGMA busy_timeout=5000")
        _conn.executescript(SCHEMA)
        if path is None:
            os.chmod(config.DB_PATH, 0o600)


@contextmanager
def _tx() -> Iterator[sqlite3.Connection]:
    with _lock:
        assert _conn is not None, "store.init() not called"
        _conn.execute("BEGIN IMMEDIATE")
        try:
            yield _conn
        except BaseException:
            _conn.execute("ROLLBACK")
            raise
        else:
            _conn.execute("COMMIT")


def _row(r: sqlite3.Row | None) -> dict[str, Any] | None:
    if r is None:
        return None
    d = dict(r)
    d["tables"] = json.loads(d["tables"])
    d["commands"] = json.loads(d["commands"])
    return d


# ---- grants -------------------------------------------------------------------------------


def new_grant_id() -> str:
    return config.ROLE_PREFIX + secrets.token_hex(5)


def insert_grant(g: dict[str, Any]) -> None:
    now = time.time()
    with _tx() as c:
        c.execute(
            "INSERT INTO grants (id, db_type, scope, tables, commands, requested_for, issued_by,"
            " ttl_seconds, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                g["id"], g["db_type"], g["scope"], json.dumps(g["tables"]), json.dumps(g["commands"]),
                g["requested_for"], g["issued_by"], g["ttl_seconds"], "issuing", now, now,
            ),
        )  # fmt: skip


def update_grant(grant_id: str, **fields: Any) -> None:
    fields["updated_at"] = time.time()
    cols = ", ".join(f"{k} = ?" for k in fields)
    with _tx() as c:
        c.execute(f"UPDATE grants SET {cols} WHERE id = ?", (*fields.values(), grant_id))  # noqa: S608


def get_grant(grant_id: str) -> dict[str, Any] | None:
    with _lock:
        assert _conn is not None
        return _row(_conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone())


def list_grants(statuses: tuple[str, ...] | None = None, limit: int = 200) -> list[dict[str, Any]]:
    with _lock:
        assert _conn is not None
        if statuses:
            q = ",".join("?" * len(statuses))
            rows = _conn.execute(
                f"SELECT * FROM grants WHERE status IN ({q}) ORDER BY created_at DESC LIMIT ?",  # noqa: S608
                (*statuses, limit),
            ).fetchall()
        else:
            rows = _conn.execute("SELECT * FROM grants ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_row(r) for r in rows]  # type: ignore[misc]


# ---- audit --------------------------------------------------------------------------------


def audit(request_id: str | None, grant_id: str | None, actor: str, action: str, result: str, detail: str = "") -> None:
    with _tx() as c:
        c.execute(
            "INSERT INTO audit (ts, request_id, grant_id, actor, action, result, detail) VALUES (?,?,?,?,?,?,?)",
            (time.time(), request_id, grant_id, actor, action, result, detail[:500]),
        )


def audit_exists(action: str, detail: str) -> bool:
    with _lock:
        assert _conn is not None
        return _conn.execute("SELECT 1 FROM audit WHERE action = ? AND detail = ?", (action, detail)).fetchone() is not None


# ---- sessions -----------------------------------------------------------------------------


def create_session(username: str, vault_token: str) -> tuple[str, str]:
    sid, csrf, now = secrets.token_urlsafe(32), secrets.token_urlsafe(32), time.time()
    with _tx() as c:
        c.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?)", (sid, username, csrf, vault_token, now, now, now))
    return sid, csrf


def get_session(sid: str) -> dict[str, Any] | None:
    with _lock:
        assert _conn is not None
        r = _conn.execute("SELECT * FROM sessions WHERE sid = ?", (sid,)).fetchone()
        return dict(r) if r else None


def touch_session(sid: str, checked: bool = False) -> None:
    now = time.time()
    with _tx() as c:
        if checked:
            c.execute("UPDATE sessions SET last_seen = ?, last_check = ? WHERE sid = ?", (now, now, sid))
        else:
            c.execute("UPDATE sessions SET last_seen = ? WHERE sid = ?", (now, sid))


def delete_session(sid: str) -> None:
    with _tx() as c:
        c.execute("DELETE FROM sessions WHERE sid = ?", (sid,))


def purge_sessions() -> list[dict[str, Any]]:
    """Delete sessions past the absolute/idle limits; return them so their Vault tokens can be revoked."""
    now = time.time()
    with _tx() as c:
        rows = c.execute(
            "SELECT * FROM sessions WHERE created_at < ? OR last_seen < ?",
            (now - config.SESSION_ABSOLUTE_SECONDS, now - config.SESSION_IDLE_SECONDS),
        ).fetchall()
        c.execute(
            "DELETE FROM sessions WHERE created_at < ? OR last_seen < ?",
            (now - config.SESSION_ABSOLUTE_SECONDS, now - config.SESSION_IDLE_SECONDS),
        )
        return [dict(r) for r in rows]
