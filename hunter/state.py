"""Run state in one SQLite file per target. This is the single source of
truth for what ran, what is blocked and what is left; Markdown files are
only generated views of it."""

from __future__ import annotations

import datetime as _dt
import json
import time
import sqlite3
from pathlib import Path
from typing import Iterable

PENDING = "PENDING"
RUNNING = "RUNNING"
DONE = "DONE"
PARTIAL = "PARTIAL"
BLOCKED = "BLOCKED"
FAILED = "FAILED"
NOT_APPLICABLE = "NOT_APPLICABLE"
NOT_BUILT = "NOT_BUILT"

PHASE_STATES = (PENDING, RUNNING, DONE, PARTIAL, BLOCKED, FAILED, NOT_APPLICABLE, NOT_BUILT)
# A phase in one of these states is not run again unless its code version or
# its inputs change.
SETTLED = (DONE, NOT_APPLICABLE)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS phases (
    phase_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    version TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS blockers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phase_id TEXT NOT NULL,
    need TEXT NOT NULL,
    detail TEXT,
    watch_files TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    created_at TEXT NOT NULL,
    closed_at TEXT,
    UNIQUE (phase_id, need)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    phase_id TEXT,
    message TEXT
);
CREATE TABLE IF NOT EXISTS agent_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    phase_id TEXT,
    role TEXT,
    profile TEXT,
    model TEXT,
    ok INTEGER,
    exit_code INTEGER,
    subtype TEXT,
    turns INTEGER,
    cost_usd REAL,
    duration_s REAL,
    session_id TEXT,
    log_path TEXT
);
CREATE TABLE IF NOT EXISTS inventory (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    data TEXT NOT NULL,
    first_phase TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (kind, key)
);
CREATE INDEX IF NOT EXISTS idx_inventory_kind ON inventory(kind);
"""


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


class State:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.path = db_path
        self.db = sqlite3.connect(str(db_path), timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # meta -----------------------------------------------------------------
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # phases ---------------------------------------------------------------
    def ensure_phase(self, phase_id: str, name: str) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO phases(phase_id, name, status) VALUES(?, ?, ?)",
            (phase_id, name, PENDING))
        self.db.execute("UPDATE phases SET name=? WHERE phase_id=?", (name, phase_id))

    def prune_phases(self, keep_ids: list[str]) -> list[str]:
        """Remove phase rows no longer in the pipeline (e.g. a phase that was
        renamed), so a stale id does not linger forever as PENDING."""
        keep = set(keep_ids)
        stale = [r["phase_id"] for r in self.phases() if r["phase_id"] not in keep]
        for pid in stale:
            self.db.execute("DELETE FROM phases WHERE phase_id=?", (pid,))
        return stale

    def phase(self, phase_id: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM phases WHERE phase_id=?", (phase_id,)).fetchone()

    def phases(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM phases ORDER BY phase_id"))

    def start_phase(self, phase_id: str, version: str) -> None:
        self.db.execute(
            "UPDATE phases SET status=?, version=?, attempts=attempts+1, started_at=?, finished_at=NULL "
            "WHERE phase_id=?", (RUNNING, version, now(), phase_id))
        self.clear_progress(phase_id)
        self.event("phase_start", phase_id, f"version {version}")

    # progress -------------------------------------------------------------
    def set_progress(self, phase_id: str, step: str, done: int | None, total: int | None,
                     unit: str = "") -> None:
        """What a running phase is doing: a step name and, when countable,
        how many items of how many are done. done=None: not countable."""
        key = f"progress:{phase_id}"
        old = self.get_progress(phase_id)
        started = old["step_started"] if old and old.get("step") == step else time.time()
        self.set_meta(key, json.dumps({"step": step, "done": done, "total": total, "unit": unit,
                                       "step_started": started, "updated": time.time()}))

    def get_progress(self, phase_id: str) -> dict | None:
        raw = self.get_meta(f"progress:{phase_id}")
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return None

    def clear_progress(self, phase_id: str) -> None:
        self.db.execute("DELETE FROM meta WHERE key=?", (f"progress:{phase_id}",))

    def finish_phase(self, phase_id: str, status: str, summary: str) -> None:
        if status not in PHASE_STATES:
            raise ValueError(f"invalid phase status {status}")
        self.db.execute(
            "UPDATE phases SET status=?, finished_at=?, summary=? WHERE phase_id=?",
            (status, now(), summary, phase_id))
        self.event("phase_end", phase_id, f"{status}: {summary}")

    def reset_phase(self, phase_id: str, reason: str, reset_attempts: bool = False) -> None:
        if reset_attempts:
            self.db.execute("UPDATE phases SET status=?, attempts=0 WHERE phase_id=?", (PENDING, phase_id))
        else:
            self.db.execute("UPDATE phases SET status=? WHERE phase_id=?", (PENDING, phase_id))
        self.event("phase_reset", phase_id, reason)

    def interrupt_running(self, reason: str) -> list[str]:
        """Called on startup and on shutdown: a phase left RUNNING was cut off."""
        rows = list(self.db.execute("SELECT phase_id FROM phases WHERE status=?", (RUNNING,)))
        for row in rows:
            self.db.execute(
                "UPDATE phases SET status=?, attempts=MAX(attempts-1, 0) WHERE phase_id=?",
                (PENDING, row["phase_id"]))
            self.event("phase_interrupted", row["phase_id"], reason)
        return [row["phase_id"] for row in rows]

    # blockers -------------------------------------------------------------
    def add_blocker(self, phase_id: str, need: str, detail: str = "",
                    watch_files: Iterable[str] = ()) -> tuple[int, bool]:
        """Returns (blocker id, created). An identical open blocker is reused
        so the operator is not notified twice for the same thing."""
        existing = self.db.execute(
            "SELECT id, status FROM blockers WHERE phase_id=? AND need=?", (phase_id, need)).fetchone()
        files = json.dumps(sorted(set(watch_files)))
        if existing:
            if existing["status"] == "OPEN":
                return existing["id"], False
            self.db.execute(
                "UPDATE blockers SET status='OPEN', detail=?, watch_files=?, created_at=?, closed_at=NULL "
                "WHERE id=?", (detail, files, now(), existing["id"]))
            self.event("blocker_reopened", phase_id, need)
            return existing["id"], True
        cur = self.db.execute(
            "INSERT INTO blockers(phase_id, need, detail, watch_files, status, created_at) "
            "VALUES(?, ?, ?, ?, 'OPEN', ?)", (phase_id, need, detail, files, now()))
        self.event("blocker", phase_id, need)
        return cur.lastrowid, True

    def open_blockers(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM blockers WHERE status='OPEN' ORDER BY id"))

    def blockers(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM blockers ORDER BY id"))

    def close_blocker(self, blocker_id: int, status: str) -> None:
        if status not in ("RESOLVED", "UNRESOLVED"):
            raise ValueError(status)
        self.db.execute("UPDATE blockers SET status=?, closed_at=? WHERE id=?", (status, now(), blocker_id))
        row = self.db.execute("SELECT phase_id, need FROM blockers WHERE id=?", (blocker_id,)).fetchone()
        self.event(f"blocker_{status.lower()}", row["phase_id"] if row else None, row["need"] if row else "")

    # events and agent runs -------------------------------------------------
    def event(self, kind: str, phase_id: str | None, message: str) -> None:
        self.db.execute(
            "INSERT INTO events(ts, kind, phase_id, message) VALUES(?, ?, ?, ?)",
            (now(), kind, phase_id, message))

    def events(self, limit: int = 50) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)))

    def record_agent_run(self, **fields) -> None:
        fields.setdefault("ts", now())
        columns = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        self.db.execute(f"INSERT INTO agent_runs({columns}) VALUES({marks})", tuple(fields.values()))

    # inventory: hosts, services and other records that phases build on ------
    def put(self, kind: str, key: str, data: dict, phase_id: str | None = None,
            merge: bool = True) -> dict:
        """Create or update one inventory record. With merge=True the new
        data is merged into the existing record (new keys win)."""
        existing = self.get(kind, key)
        if existing is not None and merge:
            merged = {**existing, **data}
        else:
            merged = dict(data)
        self.db.execute(
            "INSERT INTO inventory(kind, key, data, first_phase, updated_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(kind, key) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
            (kind, key, json.dumps(merged), phase_id, now()))
        return merged

    def get(self, kind: str, key: str) -> dict | None:
        row = self.db.execute("SELECT data FROM inventory WHERE kind=? AND key=?", (kind, key)).fetchone()
        return json.loads(row["data"]) if row else None

    def items(self, kind: str) -> list[dict]:
        rows = self.db.execute("SELECT key, data FROM inventory WHERE kind=? ORDER BY key", (kind,))
        out = []
        for row in rows:
            record = json.loads(row["data"])
            record.setdefault("key", row["key"])
            out.append(record)
        return out

    def count(self, kind: str, where: str = "") -> int:
        sql = "SELECT COUNT(*) AS n FROM inventory WHERE kind=?"
        return self.db.execute(sql + (f" AND {where}" if where else ""), (kind,)).fetchone()["n"]

    def agent_totals(self) -> dict:
        row = self.db.execute(
            "SELECT COUNT(*) AS runs, COALESCE(SUM(cost_usd), 0) AS cost, "
            "COALESCE(SUM(ok), 0) AS ok FROM agent_runs").fetchone()
        return dict(row)
