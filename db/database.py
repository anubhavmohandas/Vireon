"""
db/database.py — SQLite database wrapper

Uses stdlib sqlite3 (no new dependencies).
All writes go through run_in_executor so they never block the asyncio event loop.

Schema:
  investigations       — one row per INV-XXXX run
  timeline_events      — append-only event log
  agent_results        — one row per agent per investigation
  decision_log         — audit trail of coordinator decisions
  confidence_evolution — confidence snapshots for graph UI
"""

import asyncio
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path


_DEFAULT_DB_PATH = os.getenv("VIREON_DB_PATH", "vireon.db")


CREATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    inv_id          TEXT PRIMARY KEY,
    repo_path       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running',
    days            INTEGER NOT NULL DEFAULT 7,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    fused_confidence REAL,
    error           TEXT
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    inv_id      TEXT NOT NULL,
    ts          TEXT NOT NULL,
    agent       TEXT NOT NULL,
    event       TEXT NOT NULL,
    detail      TEXT,
    confidence  REAL,
    FOREIGN KEY (inv_id) REFERENCES investigations(inv_id)
);

CREATE TABLE IF NOT EXISTS agent_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    inv_id      TEXT NOT NULL,
    agent       TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    confidence  REAL NOT NULL,
    evidence    TEXT,      -- JSON
    metadata    TEXT,      -- JSON
    duration_ms INTEGER,
    created_at  TEXT NOT NULL,
    UNIQUE (inv_id, agent),
    FOREIGN KEY (inv_id) REFERENCES investigations(inv_id)
);

CREATE TABLE IF NOT EXISTS decision_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    inv_id      TEXT NOT NULL,
    ts          TEXT NOT NULL,
    agent       TEXT NOT NULL,
    action      TEXT NOT NULL,
    reason      TEXT,
    metadata    TEXT,      -- JSON
    FOREIGN KEY (inv_id) REFERENCES investigations(inv_id)
);

CREATE TABLE IF NOT EXISTS confidence_evolution (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    inv_id      TEXT NOT NULL,
    ts          TEXT NOT NULL,
    agent       TEXT NOT NULL,
    confidence  REAL NOT NULL,
    label       TEXT,
    FOREIGN KEY (inv_id) REFERENCES investigations(inv_id)
);

CREATE INDEX IF NOT EXISTS idx_timeline_inv   ON timeline_events(inv_id);
CREATE INDEX IF NOT EXISTS idx_results_inv    ON agent_results(inv_id);
CREATE INDEX IF NOT EXISTS idx_decisions_inv  ON decision_log(inv_id);
CREATE INDEX IF NOT EXISTS idx_conf_inv       ON confidence_evolution(inv_id);
"""


class Database:
    """
    Thin asyncio-friendly SQLite wrapper.

    All public methods are async — heavy work runs in a thread via run_in_executor
    so the event loop is never blocked.

    Usage:
        db = Database()
        await db.init()
        await db.insert_investigation(inv_id, repo_path, days)
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH):
        self.db_path = db_path
        self._loop: asyncio.AbstractEventLoop | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def init(self):
        """Create tables if they don't exist."""
        self._loop = asyncio.get_event_loop()
        await self._run(self._create_schema)

    def _create_schema(self):
        with self._connect() as conn:
            conn.executescript(CREATE_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")   # safe concurrent reads
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    async def _run(self, fn, *args):
        """Run a sync DB function in a thread pool executor."""
        loop = self._loop or asyncio.get_event_loop()
        return await loop.run_in_executor(None, fn, *args)

    # ── Investigations ────────────────────────────────────────────────────────

    async def insert_investigation(self, inv_id: str, repo_path: str, days: int):
        def _write(inv_id, repo_path, days):
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO investigations
                        (inv_id, repo_path, days, status, started_at)
                    VALUES (?, ?, ?, 'running', ?)
                    """,
                    (inv_id, repo_path, days, datetime.now().isoformat()),
                )
                conn.commit()
        await self._run(_write, inv_id, repo_path, days)

    async def update_investigation_status(
        self,
        inv_id: str,
        status: str,
        fused_confidence: float | None = None,
        error: str | None = None,
    ):
        def _write(inv_id, status, fused_confidence, error):
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE investigations
                    SET status = ?,
                        fused_confidence = COALESCE(?, fused_confidence),
                        error = COALESCE(?, error),
                        completed_at = CASE WHEN ? != 'running' THEN ? ELSE completed_at END
                    WHERE inv_id = ?
                    """,
                    (status, fused_confidence, error, status, datetime.now().isoformat(), inv_id),
                )
                conn.commit()
        await self._run(_write, inv_id, status, fused_confidence, error)

    async def get_investigation(self, inv_id: str) -> dict | None:
        def _read(inv_id):
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM investigations WHERE inv_id = ?", (inv_id,)
                ).fetchone()
                return dict(row) if row else None
        return await self._run(_read, inv_id)

    async def list_investigations(self, limit: int = 50) -> list[dict]:
        def _read(limit):
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM investigations ORDER BY started_at DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
        return await self._run(_read, limit)

    # ── Timeline events ───────────────────────────────────────────────────────

    async def insert_timeline_event(
        self, inv_id: str, ts: str, agent: str, event: str,
        detail: str = "", confidence: float | None = None,
    ):
        def _write(inv_id, ts, agent, event, detail, confidence):
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO timeline_events (inv_id, ts, agent, event, detail, confidence)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (inv_id, ts, agent, event, detail, confidence),
                )
                conn.commit()
        await self._run(_write, inv_id, ts, agent, event, detail, confidence)

    async def get_timeline(self, inv_id: str) -> list[dict]:
        def _read(inv_id):
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM timeline_events WHERE inv_id = ? ORDER BY id", (inv_id,)
                ).fetchall()
                return [dict(r) for r in rows]
        return await self._run(_read, inv_id)

    # ── Agent results ─────────────────────────────────────────────────────────

    async def upsert_agent_result(
        self, inv_id: str, agent: str, verdict: str, confidence: float,
        evidence: list, metadata: dict, duration_ms: int,
    ):
        def _write(inv_id, agent, verdict, confidence, evidence, metadata, duration_ms):
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO agent_results
                        (inv_id, agent, verdict, confidence, evidence, metadata, duration_ms, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(inv_id, agent) DO UPDATE SET
                        verdict     = excluded.verdict,
                        confidence  = excluded.confidence,
                        evidence    = excluded.evidence,
                        metadata    = excluded.metadata,
                        duration_ms = excluded.duration_ms,
                        created_at  = excluded.created_at
                    """,
                    (
                        inv_id, agent, verdict, confidence,
                        json.dumps(evidence), json.dumps(metadata),
                        duration_ms, datetime.now().isoformat(),
                    ),
                )
                conn.commit()
        await self._run(_write, inv_id, agent, verdict, confidence, evidence, metadata, duration_ms)

    async def get_agent_results(self, inv_id: str) -> list[dict]:
        def _read(inv_id):
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM agent_results WHERE inv_id = ? ORDER BY id", (inv_id,)
                ).fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    d["evidence"] = json.loads(d["evidence"] or "[]")
                    d["metadata"] = json.loads(d["metadata"] or "{}")
                    results.append(d)
                return results
        return await self._run(_read, inv_id)

    # ── Decision log ──────────────────────────────────────────────────────────

    async def insert_decision(
        self, inv_id: str, agent: str, action: str,
        reason: str = "", metadata: dict | None = None,
    ):
        def _write(inv_id, agent, action, reason, metadata):
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO decision_log (inv_id, ts, agent, action, reason, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        inv_id, datetime.now().isoformat(),
                        agent, action, reason, json.dumps(metadata or {}),
                    ),
                )
                conn.commit()
        await self._run(_write, inv_id, agent, action, reason, metadata)

    async def get_decisions(self, inv_id: str) -> list[dict]:
        def _read(inv_id):
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM decision_log WHERE inv_id = ? ORDER BY id", (inv_id,)
                ).fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    d["metadata"] = json.loads(d["metadata"] or "{}")
                    results.append(d)
                return results
        return await self._run(_read, inv_id)

    # ── Confidence evolution ──────────────────────────────────────────────────

    async def insert_confidence_snapshot(
        self, inv_id: str, ts: str, agent: str, confidence: float, label: str = "",
    ):
        def _write(inv_id, ts, agent, confidence, label):
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO confidence_evolution (inv_id, ts, agent, confidence, label)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (inv_id, ts, agent, confidence, label),
                )
                conn.commit()
        await self._run(_write, inv_id, ts, agent, confidence, label)

    async def get_confidence_evolution(self, inv_id: str) -> list[dict]:
        def _read(inv_id):
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM confidence_evolution WHERE inv_id = ? ORDER BY id", (inv_id,)
                ).fetchall()
                return [dict(r) for r in rows]
        return await self._run(_read, inv_id)


# ── Singleton for API layer ───────────────────────────────────────────────────

_db_instance: Database | None = None


def get_db() -> Database:
    """Return the singleton Database instance (must call init() first)."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
