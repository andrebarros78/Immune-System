from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from .audit import AuditLedger


REQUIRED_GATES = (
    "scope_explicit",
    "observable_result_achieved",
    "relevant_tests_passed",
    "regression_validated",
    "recovery_validated",
    "security_validated",
    "evidence_preserved",
    "no_critical_blocker",
    "independent_audit_passed",
)


@dataclass(frozen=True)
class MissionProof:
    scope_id: str
    proven: bool
    missing_gates: tuple[str, ...]
    gates_digest: str
    signature: str


class MissionProofEngine:
    """Calcula e assina MISSION_PROVEN; o motor durável verifica a assinatura."""

    def __init__(self, audit: AuditLedger, secret: bytes):
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
            raise ValueError("proof secret must contain at least 32 bytes")
        self.audit = audit
        self._secret = bytes(secret)

    @staticmethod
    def _gates_digest(gates: dict[str, Any]) -> str:
        normalized = {name: gates.get(name) is True for name in REQUIRED_GATES}
        raw = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _payload(scope_id: str, proven: bool, missing: tuple[str, ...], gates_digest: str) -> bytes:
        raw = {
            "scope_id": scope_id,
            "proven": bool(proven),
            "missing_gates": list(missing),
            "gates_digest": gates_digest,
        }
        return json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def evaluate(self, scope_id: str, gates: dict[str, Any]) -> MissionProof:
        missing = tuple(name for name in REQUIRED_GATES if gates.get(name) is not True)
        proven = not missing
        digest = self._gates_digest(gates)
        signature = hmac.new(
            self._secret,
            self._payload(scope_id, proven, missing, digest),
            hashlib.sha256,
        ).hexdigest()
        proof = MissionProof(
            scope_id=scope_id,
            proven=proven,
            missing_gates=missing,
            gates_digest=digest,
            signature=signature,
        )
        self.audit.append(
            actor="acceptance-engine",
            action="mission_proof_evaluated",
            mission_id=scope_id,
            payload={
                "proven": proof.proven,
                "missing_gates": list(missing),
                "gates_digest": digest,
            },
        )
        return proof

    def verify(self, proof: MissionProof, scope_id: str) -> bool:
        if proof.scope_id != scope_id or not proof.proven or proof.missing_gates:
            return False
        expected = hmac.new(
            self._secret,
            self._payload(proof.scope_id, proof.proven, proof.missing_gates, proof.gates_digest),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, proof.signature)
