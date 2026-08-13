from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from .models import TaskLease


class StateError(RuntimeError):
    pass


class SQLiteStateStore:
    """Estado durável local com WAL, transações imediatas e idempotência."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS missions (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL,
                state TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                state TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 0,
                idempotency_key TEXT NOT NULL UNIQUE,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                next_run_at REAL NOT NULL,
                lease_owner TEXT,
                lease_until REAL,
                last_error TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tasks_claim
                ON tasks(state, next_run_at, priority DESC, created_at);
            CREATE TABLE IF NOT EXISTS transitions (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                reason TEXT NOT NULL,
                at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                ts REAL NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                mission_id TEXT,
                payload_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            );
            """
        )

    def close(self) -> None:
        self.conn.close()

    def create_mission(self, mission_id: str, system_id: str, state: str = "CREATED", *, now: float | None = None) -> None:
        ts = time.time() if now is None else float(now)
        with self.conn:
            self.conn.execute(
                "INSERT INTO missions(id, system_id, state, created_at, updated_at) VALUES(?,?,?,?,?)",
                (mission_id, system_id, state, ts, ts),
            )
            self.conn.execute(
                "INSERT INTO transitions(entity_type, entity_id, from_state, to_state, reason, at) VALUES(?,?,?,?,?,?)",
                ("mission", mission_id, None, state, "created", ts),
            )

    def get_mission(self, mission_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM missions WHERE id=?", (mission_id,)).fetchone()
        return dict(row) if row else None

    def set_mission_state(self, mission_id: str, to_state: str, reason: str, *, now: float | None = None) -> None:
        ts = time.time() if now is None else float(now)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT state, version FROM missions WHERE id=?", (mission_id,)).fetchone()
            if not row:
                raise StateError("mission not found")
            self.conn.execute(
                "UPDATE missions SET state=?, version=?, updated_at=? WHERE id=?",
                (to_state, int(row["version"]) + 1, ts, mission_id),
            )
            self.conn.execute(
                "INSERT INTO transitions(entity_type, entity_id, from_state, to_state, reason, at) VALUES(?,?,?,?,?,?)",
                ("mission", mission_id, row["state"], to_state, reason, ts),
            )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def submit_task(
        self,
        mission_id: str,
        kind: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        priority: int = 0,
        max_attempts: int = 3,
        task_id: str | None = None,
        now: float | None = None,
    ) -> str:
        ts = time.time() if now is None else float(now)
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        existing = self.conn.execute(
            "SELECT id FROM tasks WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        if existing:
            return str(existing["id"])
        tid = task_id or str(uuid.uuid4())
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            existing = self.conn.execute(
                "SELECT id FROM tasks WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if existing:
                self.conn.execute("COMMIT")
                return str(existing["id"])
            self.conn.execute(
                """
                INSERT INTO tasks(
                    id, mission_id, kind, payload_json, state, priority, idempotency_key,
                    attempts, max_attempts, next_run_at, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    tid,
                    mission_id,
                    kind,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    "QUEUED",
                    int(priority),
                    idempotency_key,
                    0,
                    int(max_attempts),
                    ts,
                    ts,
                    ts,
                ),
            )
            self.conn.execute(
                "INSERT INTO transitions(entity_type, entity_id, from_state, to_state, reason, at) VALUES(?,?,?,?,?,?)",
                ("task", tid, None, "QUEUED", "submitted", ts),
            )
            self.conn.execute("COMMIT")
            return tid
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["payload"] = json.loads(result.pop("payload_json"))
        return result

    def recover_expired_leases(self, *, now: float | None = None) -> int:
        ts = time.time() if now is None else float(now)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self.conn.execute(
                "SELECT id FROM tasks WHERE state='RUNNING' AND lease_until IS NOT NULL AND lease_until<=?",
                (ts,),
            ).fetchall()
            for row in rows:
                self.conn.execute(
                    "UPDATE tasks SET state='QUEUED', lease_owner=NULL, lease_until=NULL, updated_at=? WHERE id=?",
                    (ts, row["id"]),
                )
                self.conn.execute(
                    "INSERT INTO transitions(entity_type, entity_id, from_state, to_state, reason, at) VALUES(?,?,?,?,?,?)",
                    ("task", row["id"], "RUNNING", "QUEUED", "lease_expired_recovered", ts),
                )
            self.conn.execute("COMMIT")
            return len(rows)
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def claim_next(
        self,
        worker_id: str,
        *,
        lease_seconds: float = 30,
        now: float | None = None,
        mission_id: str | None = None,
    ) -> TaskLease | None:
        ts = time.time() if now is None else float(now)
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.recover_expired_leases(now=ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            if mission_id is None:
                sql = """
                    SELECT * FROM tasks
                    WHERE state='QUEUED' AND next_run_at<=?
                    ORDER BY priority DESC, created_at ASC
                    LIMIT 1
                """
                params = (ts,)
            else:
                sql = """
                    SELECT * FROM tasks
                    WHERE state='QUEUED' AND next_run_at<=? AND mission_id=?
                    ORDER BY priority DESC, created_at ASC
                    LIMIT 1
                """
                params = (ts, mission_id)
            row = self.conn.execute(sql, params).fetchone()
            if not row:
                self.conn.execute("COMMIT")
                return None
            lease_until = ts + float(lease_seconds)
            attempts = int(row["attempts"]) + 1
            self.conn.execute(
                """
                UPDATE tasks
                SET state='RUNNING', attempts=?, lease_owner=?, lease_until=?, updated_at=?
                WHERE id=?
                """,
                (attempts, worker_id, lease_until, ts, row["id"]),
            )
            self.conn.execute(
                "INSERT INTO transitions(entity_type, entity_id, from_state, to_state, reason, at) VALUES(?,?,?,?,?,?)",
                ("task", row["id"], "QUEUED", "RUNNING", f"claimed:{worker_id}", ts),
            )
            self.conn.execute("COMMIT")
            return TaskLease(
                id=str(row["id"]),
                mission_id=str(row["mission_id"]),
                kind=str(row["kind"]),
                payload=json.loads(row["payload_json"]),
                attempts=attempts,
                max_attempts=int(row["max_attempts"]),
                lease_owner=worker_id,
                lease_until=lease_until,
            )
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def complete_task(self, task_id: str, worker_id: str, *, now: float | None = None) -> None:
        self._finish_running(task_id, worker_id, "COMPLETED", "completed", now=now)

    def block_task(self, task_id: str, worker_id: str, reason: str, *, now: float | None = None) -> None:
        self._finish_running(task_id, worker_id, "BLOCKED", reason, now=now)

    def _finish_running(self, task_id: str, worker_id: str, state: str, reason: str, *, now: float | None = None) -> None:
        ts = time.time() if now is None else float(now)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT state, lease_owner FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not row or row["state"] != "RUNNING" or row["lease_owner"] != worker_id:
                raise StateError("task is not leased by this worker")
            self.conn.execute(
                "UPDATE tasks SET state=?, lease_owner=NULL, lease_until=NULL, updated_at=? WHERE id=?",
                (state, ts, task_id),
            )
            self.conn.execute(
                "INSERT INTO transitions(entity_type, entity_id, from_state, to_state, reason, at) VALUES(?,?,?,?,?,?)",
                ("task", task_id, "RUNNING", state, reason, ts),
            )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def fail_task(
        self,
        task_id: str,
        worker_id: str,
        error: str,
        *,
        retry_delay: float = 0,
        now: float | None = None,
    ) -> str:
        ts = time.time() if now is None else float(now)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT state, lease_owner, attempts, max_attempts FROM tasks WHERE id=?", (task_id,)
            ).fetchone()
            if not row or row["state"] != "RUNNING" or row["lease_owner"] != worker_id:
                raise StateError("task is not leased by this worker")
            retry = int(row["attempts"]) < int(row["max_attempts"])
            target = "QUEUED" if retry else "FAILED"
            next_run = ts + max(0.0, float(retry_delay))
            self.conn.execute(
                """
                UPDATE tasks SET state=?, lease_owner=NULL, lease_until=NULL,
                    next_run_at=?, last_error=?, updated_at=? WHERE id=?
                """,
                (target, next_run, error, ts, task_id),
            )
            self.conn.execute(
                "INSERT INTO transitions(entity_type, entity_id, from_state, to_state, reason, at) VALUES(?,?,?,?,?,?)",
                ("task", task_id, "RUNNING", target, f"failure:{error}", ts),
            )
            self.conn.execute("COMMIT")
            return target
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def list_tasks(self, mission_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM tasks WHERE mission_id=? ORDER BY created_at, id", (mission_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    def list_transitions(self, entity_type: str, entity_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM transitions WHERE entity_type=? AND entity_id=? ORDER BY seq",
            (entity_type, entity_id),
        ).fetchall()
        return [dict(row) for row in rows]
