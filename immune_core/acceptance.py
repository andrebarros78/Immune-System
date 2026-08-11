from __future__ import annotations

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


class MissionProofEngine:
    """Único emissor lógico de MISSION_PROVEN; calcula a partir de gates."""

    def __init__(self, audit: AuditLedger):
        self.audit = audit

    def evaluate(self, scope_id: str, gates: dict[str, Any]) -> MissionProof:
        missing = tuple(name for name in REQUIRED_GATES if gates.get(name) is not True)
        proof = MissionProof(scope_id=scope_id, proven=not missing, missing_gates=missing)
        self.audit.append(
            actor="acceptance-engine",
            action="mission_proof_evaluated",
            mission_id=scope_id,
            payload={"proven": proof.proven, "missing_gates": list(missing)},
        )
        return proof
