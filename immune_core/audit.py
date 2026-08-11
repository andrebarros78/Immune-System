from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from .storage import SQLiteStateStore


ZERO_HASH = "0" * 64


class AuditLedger:
    """Ledger append-only com encadeamento SHA-256 verificável."""

    def __init__(self, store: SQLiteStateStore):
        self.store = store

    @staticmethod
    def _canonical(event: dict[str, Any]) -> bytes:
        return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def append(
        self,
        *,
        actor: str,
        action: str,
        payload: dict[str, Any],
        mission_id: str | None = None,
        event_id: str | None = None,
        now: float | None = None,
    ) -> str:
        ts = time.time() if now is None else float(now)
        eid = event_id or str(uuid.uuid4())
        conn = self.store.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            previous = conn.execute("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = str(previous["event_hash"]) if previous else ZERO_HASH
            event = {
                "event_id": eid,
                "ts": ts,
                "actor": actor,
                "action": action,
                "mission_id": mission_id,
                "payload": payload,
                "prev_hash": prev_hash,
            }
            event_hash = hashlib.sha256(self._canonical(event)).hexdigest()
            conn.execute(
                """
                INSERT INTO audit_events(event_id, ts, actor, action, mission_id, payload_json, prev_hash, event_hash)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    eid,
                    ts,
                    actor,
                    action,
                    mission_id,
                    json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    prev_hash,
                    event_hash,
                ),
            )
            conn.execute("COMMIT")
            return event_hash
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def verify_chain(self) -> tuple[bool, int | None]:
        rows = self.store.conn.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        expected_prev = ZERO_HASH
        for row in rows:
            if row["prev_hash"] != expected_prev:
                return False, int(row["seq"])
            event = {
                "event_id": row["event_id"],
                "ts": float(row["ts"]),
                "actor": row["actor"],
                "action": row["action"],
                "mission_id": row["mission_id"],
                "payload": json.loads(row["payload_json"]),
                "prev_hash": row["prev_hash"],
            }
            expected_hash = hashlib.sha256(self._canonical(event)).hexdigest()
            if not hmac.compare_digest(expected_hash, row["event_hash"]):
                return False, int(row["seq"])
            expected_prev = row["event_hash"]
        return True, None

    def count(self) -> int:
        return int(self.store.conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
