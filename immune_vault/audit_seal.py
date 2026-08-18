from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from immune_core.audit import AuditLedger, ZERO_HASH


class AuditSealError(RuntimeError):
    pass


class AuditSealVault:
    """Signed external checkpoints make audit-history rewrites detectable."""

    def __init__(self, secret: bytes, seal_file: str | Path):
        if len(secret) < 32:
            raise ValueError("audit seal key must contain at least 32 bytes")
        self._secret = bytes(secret)
        self.seal_file = Path(seal_file)

    def _sign(self, payload: dict) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self._secret, raw, hashlib.sha256).hexdigest()

    def seal(self, ledger: AuditLedger, *, generation: int, now: float | None = None) -> dict:
        row = ledger.store.conn.execute("SELECT seq,event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        payload = {
            "generation": int(generation),
            "seq": int(row["seq"]) if row else 0,
            "head_hash": str(row["event_hash"]) if row else ZERO_HASH,
            "ts": float(time.time() if now is None else now),
        }
        record = {**payload, "signature": self._sign(payload)}
        self.seal_file.parent.mkdir(parents=True, exist_ok=True)
        with self.seal_file.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return record

    def verify_all(self) -> list[dict]:
        if not self.seal_file.is_file():
            raise AuditSealError("audit seal file missing")
        records: list[dict] = []
        last_generation = 0
        last_seq = -1
        for line in self.seal_file.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            signature = str(item.pop("signature", ""))
            if not hmac.compare_digest(self._sign(item), signature):
                raise AuditSealError("audit seal signature invalid")
            if int(item["generation"]) <= last_generation or int(item["seq"]) < last_seq:
                raise AuditSealError("audit seal rollback detected")
            last_generation = int(item["generation"])
            last_seq = int(item["seq"])
            records.append({**item, "signature": signature})
        return records
    def verify_against_ledger(self, ledger: AuditLedger) -> bool:
        records = self.verify_all()
        if not records:
            raise AuditSealError("audit seal file is empty")
        latest = records[-1]
        seq = int(latest["seq"])
        if seq == 0:
            return ledger.count() == 0 and latest["head_hash"] == ZERO_HASH
        row = ledger.store.conn.execute("SELECT event_hash FROM audit_events WHERE seq=?", (seq,)).fetchone()
        if row is None or not hmac.compare_digest(str(row["event_hash"]), str(latest["head_hash"])):
            raise AuditSealError("ledger diverges from external signed seal")
        return True
