#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
failures: list[str] = []
checks: list[dict] = []


def ok(name: str, condition: bool, detail: str = "") -> None:
    checks.append({"name": name, "passed": bool(condition), "detail": detail})
    if not condition:
        failures.append(name)


# JSON Schema structural validation without external dependencies.
contract_dir = ROOT / "contracts"
expected_contracts = {
    "system.schema.json",
    "mission.schema.json",
    "incident.schema.json",
    "task.schema.json",
    "worker.schema.json",
    "evidence.schema.json",
    "checkpoint.schema.json",
    "policy-decision.schema.json",
    "donor-component.schema.json",
    "human-exception.schema.json",
}
found = {p.name for p in contract_dir.glob("*.schema.json")}
ok("contract_set_complete", found == expected_contracts, f"found={sorted(found)}")
for path in sorted(contract_dir.glob("*.schema.json")):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        ok(f"json_parse:{path.name}", True)
        ok(f"draft2020:{path.name}", data.get("$schema", "").endswith("2020-12/schema"))
        ok(
            f"strict_object:{path.name}",
            data.get("type") == "object" and data.get("additionalProperties") is False,
        )
        ok(f"required_nonempty:{path.name}", bool(data.get("required")))
        ok(f"properties_present:{path.name}", bool(data.get("properties")))
    except Exception as exc:
        ok(f"json_parse:{path.name}", False, repr(exc))

policy_decision = json.loads(
    (contract_dir / "policy-decision.schema.json").read_text(encoding="utf-8")
)
decisions = set(policy_decision["properties"]["decision"]["enum"])
ok(
    "policy_decisions_exact",
    decisions
    == {
        "PERMITIR",
        "PERMITIR_COM_RESTRIÇÕES",
        "EXIGIR_CHECKPOINT",
        "EXIGIR_APROVAÇÃO_HUMANA",
        "BLOQUEAR",
        "CONTER_E_ESCALAR",
    },
)

# State machines: exact normative states and key transition guards.
mission = (ROOT / "state-machines/mission.yaml").read_text(encoding="utf-8")
incident = (ROOT / "state-machines/incident.yaml").read_text(encoding="utf-8")
attempt = (ROOT / "state-machines/attempt.yaml").read_text(encoding="utf-8")
for state in [
    "CREATED",
    "AUTHORIZED",
    "DISCOVERING",
    "RUNNING",
    "DEGRADED",
    "BLOCKED",
    "WAITING_HUMAN",
    "CONTAINED",
    "VALIDATING",
    "COMPLETED",
    "FAILED_SAFE",
    "CANCELLED",
]:
    ok(f"mission_state:{state}", state in mission)
for state in [
    "DETECTED",
    "CONFIRMED",
    "TRIAGED",
    "INVESTIGATING",
    "CAUSE_IDENTIFIED",
    "FIX_PLANNED",
    "FIX_TESTING",
    "FIX_APPROVED",
    "APPLYING",
    "VALIDATING",
    "MONITORING_RECOVERY",
    "RESOLVED",
    "ROLLED_BACK",
    "CONTAINED",
    "ESCALATED",
    "CLOSED_WITH_RISK",
]:
    ok(f"incident_state:{state}", state in incident)
ok("completed_requires_mission_proven", "COMPLETED requires MISSION_PROVEN" in mission)
ok(
    "attempt_no_blind_retry",
    "equivalent_retry_requires_new_evidence" in attempt
    and "each_retry_requires_technical_delta" in attempt,
)

# Constitution and policy fail-closed invariants.
dna = (ROOT / "constitution/IMUNE-DNA-001.md").read_text(encoding="utf-8")
for marker in [
    "Fail-closed",
    "Open Source Only",
    "Separação de funções",
    "checkpoint",
    "MISSION_PROVEN",
    "Loop Engineering",
]:
    ok(f"dna:{marker}", marker.lower() in dna.lower())

policy_files = sorted((ROOT / "policies").glob("*.rego"))
ok("rego_policy_count", len(policy_files) == 7, f"count={len(policy_files)}")
for path in policy_files:
    text = path.read_text(encoding="utf-8")
    ok(f"rego_package:{path.name}", text.startswith("package immune."))
    ok(f"rego_has_default:{path.name}", "default " in text)
ok(
    "authority_fail_closed",
    'default decision := "BLOQUEAR"'
    in (ROOT / "policies/authority.rego").read_text(encoding="utf-8"),
)
ok(
    "donor_fail_closed",
    'default decision := "BLOQUEAR"'
    in (ROOT / "policies/donor-oss.rego").read_text(encoding="utf-8"),
)
ok(
    "mission_proven_default_false",
    "default mission_proven := false"
    in (ROOT / "policies/mission-proven.rego").read_text(encoding="utf-8"),
)

# Contract-level scenario matrix. Runtime PolicyGuard implementation belongs to Phase 2.
def authority(i: dict) -> str:
    gates = ("mission_authorized", "system_authorized", "requester_authorized", "scope_ok")
    return "PERMITIR" if all(i.get(k) is True for k in gates) else "BLOQUEAR"


def financial(i: dict) -> str:
    gates = ("new_cost", "purchase", "subscription", "trial_with_billing_risk", "commercial_license")
    return "EXIGIR_APROVAÇÃO_HUMANA" if any(i.get(k) is True for k in gates) else "PERMITIR"


def material(i: dict) -> str:
    if i.get("disables_security_control") is True:
        return "BLOQUEAR"
    if i.get("irreversible") is True and i.get("recovery_verified") is not True:
        return "EXIGIR_APROVAÇÃO_HUMANA"
    if i.get("material_change") is True and i.get("checkpoint_valid") is not True:
        return "EXIGIR_CHECKPOINT"
    return "PERMITIR"


def donor(i: dict) -> str:
    gates = (
        "open_source",
        "license_verified",
        "origin_pinned",
        "artifact_hash_verified",
        "security_scanned",
        "laboratory_approved",
    )
    if all(i.get(k) is True for k in gates) and i.get("authority") == "adapter-only":
        return "PERMITIR_COM_RESTRIÇÕES"
    return "BLOQUEAR"


def mission_proven(i: dict) -> bool:
    gates = (
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
    return all(i.get(k) is True for k in gates)


scenarios = {
    "invalid_mission_blocked": authority({}) == "BLOQUEAR",
    "worker_scope_expansion_blocked": authority(
        {
            "mission_authorized": True,
            "system_authorized": True,
            "requester_authorized": True,
            "scope_ok": False,
        }
    )
    == "BLOQUEAR",
    "paid_action_requires_human": financial({"purchase": True})
    == "EXIGIR_APROVAÇÃO_HUMANA",
    "material_change_without_checkpoint_blocked": material({"material_change": True})
    == "EXIGIR_CHECKPOINT",
    "irreversible_without_recovery_requires_human": material({"irreversible": True})
    == "EXIGIR_APROVAÇÃO_HUMANA",
    "disable_security_control_blocked": material({"disables_security_control": True})
    == "BLOQUEAR",
    "non_oss_donor_blocked": donor({"open_source": False}) == "BLOQUEAR",
    "oss_donor_without_lab_blocked": donor(
        {
            "open_source": True,
            "license_verified": True,
            "origin_pinned": True,
            "artifact_hash_verified": True,
            "security_scanned": True,
            "laboratory_approved": False,
            "authority": "adapter-only",
        }
    )
    == "BLOQUEAR",
    "mission_proven_missing_gate_false": mission_proven({"scope_explicit": True}) is False,
    "mission_proven_all_gates_true": mission_proven(
        {
            k: True
            for k in (
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
        }
    )
    is True,
}
for name, passed in scenarios.items():
    ok(f"scenario:{name}", passed)

# Existing donor inventory must remain Open Source Only and fully collected.
lock_path = ROOT / "donors/LOCK.json"
if lock_path.exists():
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    ok("donor_inventory_policy_oss_only", lock.get("policy") == "open-source-only")
    ok("donor_inventory_no_failed_collection", lock.get("rejected_or_failed") == 0)

# Source provenance recorded from the user-provided canonical file.
manifest = json.loads((ROOT / "specification/SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
ok(
    "source_manifest_sha256_shape",
    isinstance(manifest.get("sha256"), str) and len(manifest["sha256"]) == 64,
)
ok("source_manifest_version", manifest.get("version") == "1.0")

controlled_roots = [
    "specification",
    "constitution",
    "contracts",
    "state-machines",
    "policies",
    "acceptance",
    "adr",
]
hashes: dict[str, str] = {}
for folder in controlled_roots:
    for path in sorted((ROOT / folder).rglob("*")):
        if path.is_file():
            hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()

evidence = {
    "schema": 1,
    "phase": "PHASE_1_SPECIFICATION_AND_CONTRACTS",
    "validated_at": datetime.now(timezone.utc).isoformat(),
    "source_sha256": manifest["sha256"],
    "checks": checks,
    "summary": {
        "total": len(checks),
        "passed": sum(1 for c in checks if c["passed"]),
        "failed": len(failures),
    },
    "controlled_file_sha256": hashes,
    "result": "PHASE1_PROVEN" if not failures else "PHASE1_FAILED",
    "scope_note": "PHASE1_PROVEN prova somente consistência de especificação e contratos; não é MISSION_PROVEN do produto completo.",
}
out = ROOT / "evidence/phase1-validation.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
    encoding="utf-8",
)

status = ROOT / "PHASE1_STATUS.md"
state = "PHASE1_PROVEN" if not failures else "PHASE1_FAILED"
status.write_text(
    "# Fase 1 — Especificação e Contratos\n\n"
    f"**Estado: {state}**\n\n"
    f"Checks: {evidence['summary']['passed']}/{evidence['summary']['total']} aprovados.\n\n"
    "Este estado prova somente a Fase 1. O produto completo permanece sem MISSION_PROVEN.\n",
    encoding="utf-8",
)

print(json.dumps(evidence["summary"], sort_keys=True))
if failures:
    print("FAILED:", ", ".join(failures))
    raise SystemExit(1)
print("PHASE1_PROVEN")
