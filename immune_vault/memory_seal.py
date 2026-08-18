from __future__ import annotations

import hashlib
import hmac
import json
import time

from immune_core.memory import CognitiveMemory, MemoryIntegrityError, MemoryRecord
from immune_core.storage import SQLiteStateStore


class MemorySealError(RuntimeError):
    pass


class SealedMemoryVault:
    """Promoted memory receives an independent cryptographic attestation."""

    def __init__(self, memory: CognitiveMemory, store: SQLiteStateStore, secret: bytes):
        if len(secret) < 32:
            raise ValueError("memory seal key must contain at least 32 bytes")
        self.memory = memory
        self.store = store
        self._secret = bytes(secret)
        store.conn.execute(
            "CREATE TABLE IF NOT EXISTS memory_promotion_seals (memory_id TEXT PRIMARY KEY, content_sha256 TEXT NOT NULL, validator_subject TEXT NOT NULL, sealed_at REAL NOT NULL, signature TEXT NOT NULL)"
        )

    def _signature(self, memory_id: str, content_sha256: str, validator_subject: str, sealed_at: float) -> str:
        raw = json.dumps(
            {
                "memory_id": memory_id,
                "content_sha256": content_sha256,
                "validator_subject": validator_subject,
                "sealed_at": sealed_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._secret, raw, hashlib.sha256).hexdigest()

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
        rec = self.memory.promote(
            memory_id,
            validator_token,
            validated_evidence_ids=validated_evidence_ids,
            independent_validation=independent_validation,
            reproducible=reproducible,
            now=now,
        )
        row = self.store.conn.execute(
            "SELECT validator_subject,promoted_at FROM cognitive_memory WHERE id=?", (memory_id,)
        ).fetchone()
        sealed_at = float(row["promoted_at"] if row and row["promoted_at"] is not None else (time.time() if now is None else now))
        validator = str(row["validator_subject"] if row else "")
        signature = self._signature(rec.id, rec.content_sha256, validator, sealed_at)
        self.store.conn.execute(
            "INSERT OR REPLACE INTO memory_promotion_seals(memory_id,content_sha256,validator_subject,sealed_at,signature) VALUES(?,?,?,?,?)",
            (rec.id, rec.content_sha256, validator, sealed_at, signature),
        )
        return rec

    def verify(self, memory_id: str) -> bool:
        try:
            rec = self.memory.get(memory_id)
        except MemoryIntegrityError:
            return False
        row = self.store.conn.execute("SELECT * FROM memory_promotion_seals WHERE memory_id=?", (memory_id,)).fetchone()
        if rec is None or row is None or rec.state != "PROMOTED":
            return False
        if not hmac.compare_digest(rec.content_sha256, str(row["content_sha256"])):
            return False
        expected = self._signature(memory_id, str(row["content_sha256"]), str(row["validator_subject"]), float(row["sealed_at"]))
        return hmac.compare_digest(expected, str(row["signature"]))
