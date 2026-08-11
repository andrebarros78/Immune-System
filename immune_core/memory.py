from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .audit import AuditLedger
from .identity import IdentityAuthority
from .storage import SQLiteStateStore


class MemoryError(RuntimeError):
    pass


class MemoryIntegrityError(MemoryError):
    pass


@dataclass(frozen=True)
class MemoryRecord:
    id: str
    mission_id: str | None
    kind: str
    source: str
    content: dict[str, Any]
    evidence_ids: tuple[str, ...]
    confidence: float
    state: str
    content_sha256: str
    created_at: float
    promoted_at: float | None


class CognitiveMemory:
    """Quarantine-first memory. Only independently validated evidence can be promoted."""

    def __init__(self, store: SQLiteStateStore, identity: IdentityAuthority, audit: AuditLedger):
        self.store = store
        self.identity = identity
        self.audit = audit
        self.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cognitive_memory (
                id TEXT PRIMARY KEY,
                mission_id TEXT,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                content_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                confidence REAL NOT NULL,
                state TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                promoted_at REAL,
                validator_subject TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_cognitive_memory_state_kind
                ON cognitive_memory(state, kind, created_at);
            """
        )

    @staticmethod
    def _canonical(content: dict[str, Any]) -> str:
        return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def _hash(cls, content: dict[str, Any]) -> str:
        return hashlib.sha256(cls._canonical(content).encode("utf-8")).hexdigest()

    def record(
        self,
        *,
        kind: str,
        source: str,
        content: dict[str, Any],
        evidence_ids: tuple[str, ...] | list[str] = (),
        mission_id: str | None = None,
        confidence: float = 0.0,
        now: float | None = None,
    ) -> str:
        if not kind.strip() or not source.strip() or not isinstance(content, dict):
            raise ValueError("memory kind, source and object content are required")
        confidence = float(confidence)
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("memory confidence outside 0..1")
        evidence = tuple(sorted(set(str(x).strip() for x in evidence_ids if str(x).strip())))
        memory_id = str(uuid.uuid4())
        ts = time.time() if now is None else float(now)
        canonical = self._canonical(content)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.store.conn.execute(
            """
            INSERT INTO cognitive_memory(
                id, mission_id, kind, source, content_json, evidence_json,
                confidence, state, content_sha256, created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                memory_id,
                mission_id,
                kind.strip(),
                source.strip(),
                canonical,
                json.dumps(evidence),
                confidence,
                "QUARANTINED",
                digest,
                ts,
            ),
        )
        self.audit.append(
            actor="cognitive-memory",
            action="memory_quarantined",
            mission_id=mission_id,
            payload={"memory_id": memory_id, "kind": kind.strip(), "evidence_count": len(evidence)},
        )
        return memory_id

    def _row_to_record(self, row: Any) -> MemoryRecord:
        content = json.loads(row["content_json"])
        digest = self._hash(content)
        if digest != row["content_sha256"]:
            raise MemoryIntegrityError(f"memory integrity mismatch: {row['id']}")
        return MemoryRecord(
            id=str(row["id"]),
            mission_id=row["mission_id"],
            kind=str(row["kind"]),
            source=str(row["source"]),
            content=content,
            evidence_ids=tuple(json.loads(row["evidence_json"])),
            confidence=float(row["confidence"]),
            state=str(row["state"]),
            content_sha256=str(row["content_sha256"]),
            created_at=float(row["created_at"]),
            promoted_at=float(row["promoted_at"]) if row["promoted_at"] is not None else None,
        )

    def get(self, memory_id: str) -> MemoryRecord | None:
        row = self.store.conn.execute("SELECT * FROM cognitive_memory WHERE id=?", (memory_id,)).fetchone()
        return self._row_to_record(row) if row else None

    def promote(
        self,
        memory_id: str,
        validator_token: str,
        *,
        validated_evidence_ids: tuple[str, ...] | list[str],
        independent_validation: bool,
        reproducible: bool,
        now: int | None = None,
    ) -> MemoryRecord:
        principal = self.identity.verify(validator_token, required_scope="memory:promote", now=now)
        record = self.get(memory_id)
        if record is None:
            raise MemoryError("memory not found")
        if record.state != "QUARANTINED":
            raise MemoryError("only quarantined memory can be promoted")
        validated = set(str(x) for x in validated_evidence_ids)
        if not record.evidence_ids:
            raise MemoryError("memory without evidence cannot be promoted")
        if not set(record.evidence_ids).issubset(validated):
            raise MemoryError("not all memory evidence was validated")
        if not independent_validation or not reproducible:
            raise MemoryError("memory promotion requires independent reproducible validation")
        ts = float(time.time() if now is None else now)
        self.store.conn.execute(
            "UPDATE cognitive_memory SET state='PROMOTED', promoted_at=?, validator_subject=? WHERE id=?",
            (ts, principal.subject, memory_id),
        )
        self.audit.append(
            actor=principal.subject,
            action="memory_promoted",
            mission_id=record.mission_id,
            payload={"memory_id": memory_id, "evidence_count": len(record.evidence_ids)},
        )
        promoted = self.get(memory_id)
        if promoted is None:
            raise MemoryError("memory disappeared after promotion")
        return promoted

    def reject(self, memory_id: str, validator_token: str, reason: str, *, now: int | None = None) -> None:
        principal = self.identity.verify(validator_token, required_scope="memory:promote", now=now)
        record = self.get(memory_id)
        if record is None or record.state != "QUARANTINED":
            raise MemoryError("only quarantined memory can be rejected")
        self.store.conn.execute("UPDATE cognitive_memory SET state='REJECTED', validator_subject=? WHERE id=?", (principal.subject, memory_id))
        self.audit.append(
            actor=principal.subject,
            action="memory_rejected",
            mission_id=record.mission_id,
            payload={"memory_id": memory_id, "reason": reason},
        )

    def recall_promoted(self, *, kind: str | None = None, mission_id: str | None = None, limit: int = 20) -> list[MemoryRecord]:
        if limit < 1 or limit > 200:
            raise ValueError("memory recall limit outside 1..200")
        clauses = ["state='PROMOTED'"]
        params: list[Any] = []
        if kind:
            clauses.append("kind=?")
            params.append(kind)
        if mission_id:
            clauses.append("(mission_id=? OR mission_id IS NULL)")
            params.append(mission_id)
        sql = "SELECT * FROM cognitive_memory WHERE " + " AND ".join(clauses) + " ORDER BY promoted_at DESC LIMIT ?"
        params.append(int(limit))
        rows = self.store.conn.execute(sql, tuple(params)).fetchall()
        return [self._row_to_record(row) for row in rows]
