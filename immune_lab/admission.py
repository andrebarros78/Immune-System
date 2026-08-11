"""Porta de laboratório: nenhuma peça externa ganha autoridade por presença."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable


class Decision(str, Enum):
    REJECTED = "rejected"
    QUARANTINED = "quarantined"
    APPROVED = "approved"


REQUIRED_EVIDENCE = (
    "origin_integrity",
    "license_audit",
    "security_scan",
    "functional_test",
    "isolation_test",
    "rollback_test",
)


@dataclass(frozen=True)
class LabResult:
    donor_id: str
    capability: str
    decision: Decision
    authority: str
    executable: bool
    missing_evidence: tuple[str, ...]
    reason: str


def evaluate_donor(donor: dict[str, Any], evidence: dict[str, Any] | None = None) -> LabResult:
    evidence = evidence or {}
    donor_id = str(donor.get("id", "")).strip()
    capability = str(donor.get("purpose", "")).strip()

    if not donor_id or not capability or not donor.get("resolved_commit"):
        return LabResult(donor_id or "unknown", capability, Decision.REJECTED,
                         "none", False, (), "mandatory provenance is incomplete")
    if donor.get("status") not in {"collected", "metadata_verified", "artifact_collected"}:
        return LabResult(donor_id, capability, Decision.REJECTED,
                         "none", False, (), "collection failed or was rejected")

    missing = tuple(name for name in REQUIRED_EVIDENCE if evidence.get(name) is not True)
    if missing:
        return LabResult(donor_id, capability, Decision.QUARANTINED,
                         "none", False, missing, "laboratory evidence is incomplete")

    return LabResult(donor_id, capability, Decision.APPROVED,
                     "adapter-only", False, (),
                     "approved for adapter integration; execution remains policy-gated")


def build_catalog(donors: Iterable[dict[str, Any]], evidence_by_id: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    evidence_by_id = evidence_by_id or {}
    results = [evaluate_donor(d, evidence_by_id.get(str(d.get("id")), {})) for d in donors]
    return {
        "schema": 1,
        "sovereign_boundary": {
            "default_authority": "none",
            "direct_execution": False,
            "policy_guard_required": True,
            "mission_proven_required": True,
        },
        "summary": {
            "total": len(results),
            "approved": sum(r.decision is Decision.APPROVED for r in results),
            "quarantined": sum(r.decision is Decision.QUARANTINED for r in results),
            "rejected": sum(r.decision is Decision.REJECTED for r in results),
        },
        "donors": [{**asdict(r), "decision": r.decision.value} for r in results],
    }
