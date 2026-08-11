#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import tempfile
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.acceptance import REQUIRED_GATES, MissionProof, MissionProofEngine
from immune_core.audit import AuditLedger
from immune_core.engine import DurableLoopEngine
from immune_core.identity import IdentityAuthority
from immune_core.policy import PolicyGuard
from immune_core.storage import SQLiteStateStore, StateError

checks: list[dict[str, object]] = []
failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    checks.append({"name": name, "passed": bool(condition), "detail": detail})
    if not condition:
        failures.append(name)


expected_files = [
    "immune_core/__init__.py",
    "immune_core/models.py",
    "immune_core/identity.py",
    "immune_core/storage.py",
    "immune_core/audit.py",
    "immune_core/policy.py",
    "immune_core/engine.py",
    "immune_core/acceptance.py",
    "tests/phase2/test_foundation.py",
    "adr/ADR-0002-sovereign-foundation.md",
]
for rel in expected_files:
    check(f"file:{rel}", (ROOT / rel).is_file())

check("phase1_remains_proven", "PHASE1_PROVEN" in (ROOT / "PHASE1_STATUS.md").read_text(encoding="utf-8"))

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "foundation.db"
    store = SQLiteStateStore(db)
    audit = AuditLedger(store)
    identity = IdentityAuthority(b"phase2-validation-secret-material!"[:32])
    guard = PolicyGuard.from_repository(ROOT, identity, audit)
    proof_secret = b"phase2-proof-secret-material-0001"[:32]
    proof_engine = MissionProofEngine(audit, proof_secret)
    engine = DurableLoopEngine(store, audit, proof_engine)

    engine.create_mission("validation-mission", "validation-system")
    check("mission_persisted", store.get_mission("validation-mission")["state"] == "CREATED")

    token = identity.issue("validator-worker", "worker", ["execute:safe"], ttl_seconds=300, now=1000)
    base = {
        "mission_id": "validation-mission",
        "action": "validate",
        "required_scope": "execute:safe",
        "mission_authorized": True,
        "system_authorized": True,
        "scope_ok": True,
    }
    check("policy_safe_permit", guard.evaluate_token(token, dict(base), now=1001).decision == "PERMITIR")

    bad_scope = dict(base)
    bad_scope["scope_ok"] = False
    check("policy_scope_fail_closed", guard.evaluate_token(token, bad_scope, now=1001).decision == "BLOQUEAR")

    paid = dict(base)
    paid["subscription"] = True
    check("policy_financial_human_gate", guard.evaluate_token(token, paid, now=1001).decision == "EXIGIR_APROVAÇÃO_HUMANA")

    material = dict(base)
    material["material_change"] = True
    check("policy_checkpoint_gate", guard.evaluate_token(token, material, now=1001).decision == "EXIGIR_CHECKPOINT")

    security = dict(base)
    security["disables_security_control"] = True
    check("policy_security_block", guard.evaluate_token(token, security, now=1001).decision == "BLOQUEAR")

    donor = dict(base)
    donor.update({
        "donor_component": True,
        "open_source": True,
        "license_verified": True,
        "origin_pinned": True,
        "artifact_hash_verified": True,
        "security_scanned": True,
        "laboratory_approved": True,
        "authority": "adapter-only",
    })
    donor_decision = guard.evaluate_token(token, donor, now=1001)
    check("policy_donor_adapter_only", donor_decision.decision == "PERMITIR_COM_RESTRIÇÕES")
    check("policy_donor_no_direct_execution", "no_direct_execution" in donor_decision.restrictions)

    non_oss = dict(donor)
    non_oss["open_source"] = False
    check("policy_non_oss_blocked", guard.evaluate_token(token, non_oss, now=1001).decision == "BLOQUEAR")

    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    check("identity_tamper_blocked", guard.evaluate_token(tampered, dict(base), now=1001).decision == "BLOQUEAR")

    t1 = engine.submit_task("validation-mission", "probe", {"n": 1}, idempotency_key="idem-1", priority=1, now=2000)
    t1b = engine.submit_task("validation-mission", "probe", {"n": 2}, idempotency_key="idem-1", priority=1, now=2000)
    check("task_idempotent", t1 == t1b and len(store.list_tasks("validation-mission")) == 1)

    high = engine.submit_task("validation-mission", "critical", {}, idempotency_key="high", priority=100, now=2000)
    lease = engine.claim_next("worker-a", lease_seconds=5, now=2000)
    check("priority_claim", lease is not None and lease.id == high)
    engine.block_task(lease, "isolated blocker", now=2001)
    next_lease = engine.claim_next("worker-b", now=2002)
    check("blocked_task_does_not_stall_queue", next_lease is not None and next_lease.id == t1)
    engine.complete_task(next_lease, now=2003)

    retry_id = engine.submit_task("validation-mission", "retry", {}, idempotency_key="retry", max_attempts=2, now=3000)
    r1 = engine.claim_next("worker-r", now=3000)
    check("retry_task_claimed", r1 is not None and r1.id == retry_id)
    check("retry_first_failure_requeues", engine.fail_task(r1, "first", now=3001) == "QUEUED")
    r2 = engine.claim_next("worker-r", now=3002)
    check("retry_second_claim_attempt_incremented", r2 is not None and r2.attempts == 2)
    check("retry_exhaustion_fails", engine.fail_task(r2, "second", now=3003) == "FAILED")

    restart_id = engine.submit_task("validation-mission", "restart", {}, idempotency_key="restart", now=4000)
    restart_lease = engine.claim_next("worker-old", lease_seconds=5, now=4000)
    check("restart_task_leased", restart_lease is not None and restart_lease.id == restart_id)
    store.close()

    store = SQLiteStateStore(db)
    audit = AuditLedger(store)
    proof_engine = MissionProofEngine(audit, proof_secret)
    engine = DurableLoopEngine(store, audit, proof_engine)
    resumed = engine.resume(now=4006)
    check("restart_recovers_expired_lease", resumed.get("recovered_leases") == 1)
    resumed_lease = engine.claim_next("worker-new", now=4006)
    check("restart_task_reclaimable", resumed_lease is not None and resumed_lease.id == restart_id)
    check("restart_attempt_not_duplicated", resumed_lease is not None and resumed_lease.attempts == 2)
    engine.complete_task(resumed_lease, now=4007)

    engine.transition_mission("validation-mission", "AUTHORIZED", "authorization valid")
    engine.transition_mission("validation-mission", "RUNNING", "foundation running")
    engine.transition_mission("validation-mission", "VALIDATING", "validate")
    blocked_completion = False
    try:
        engine.transition_mission("validation-mission", "COMPLETED", "without proof")
    except StateError:
        blocked_completion = True
    check("mission_completion_requires_proof", blocked_completion)

    forged_blocked = False
    forged = MissionProof("validation-mission", True, (), "0" * 64, "0" * 64)
    try:
        engine.transition_mission("validation-mission", "COMPLETED", "forged proof", proof=forged)
    except StateError:
        forged_blocked = True
    check("mission_forged_proof_blocked", forged_blocked)

    partial = proof_engine.evaluate("validation-mission", {"scope_explicit": True})
    check("mission_proof_missing_gate_false", partial.proven is False)
    full = proof_engine.evaluate("validation-mission", {k: True for k in REQUIRED_GATES})
    check("mission_proof_all_gates_true", full.proven is True)
    engine.transition_mission("validation-mission", "COMPLETED", "proof accepted", proof=full)
    check("mission_completed_only_after_proof", store.get_mission("validation-mission")["state"] == "COMPLETED")

    chain_ok, bad = audit.verify_chain()
    check("audit_chain_valid", chain_ok and bad is None)
    before = audit.count()
    check("audit_has_material_events", before >= 10, f"events={before}")

    store.conn.execute("UPDATE audit_events SET payload_json='{}' WHERE seq=2")
    chain_ok, bad = audit.verify_chain()
    check("audit_tamper_detected", (not chain_ok) and bad == 2)

    tables = {row[0] for row in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in ("missions", "tasks", "transitions", "audit_events"):
        check(f"sqlite_table:{table}", table in tables)

    mode = store.conn.execute("PRAGMA journal_mode").fetchone()[0]
    check("sqlite_wal_mode", str(mode).lower() == "wal", str(mode))
    fk = store.conn.execute("PRAGMA foreign_keys").fetchone()[0]
    check("sqlite_foreign_keys", int(fk) == 1)

    store.close()

controlled_roots = ["immune_core", "tests/phase2", "scripts/validate_phase2.py", "adr/ADR-0002-sovereign-foundation.md"]
hashes: dict[str, str] = {}
for item in controlled_roots:
    path = ROOT / item
    if path.is_file():
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    elif path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and "__pycache__" not in child.parts and child.suffix != ".pyc":
                hashes[child.relative_to(ROOT).as_posix()] = hashlib.sha256(child.read_bytes()).hexdigest()

evidence = {
    "schema": 1,
    "phase": "PHASE_2_SOVEREIGN_FOUNDATION",
    "validated_at": datetime.now(timezone.utc).isoformat(),
    "checks": checks,
    "summary": {
        "total": len(checks),
        "passed": sum(1 for c in checks if c["passed"]),
        "failed": len(failures),
    },
    "controlled_file_sha256": hashes,
    "capabilities_proven": [
        "durable_sqlite_state",
        "wal_and_foreign_keys",
        "task_idempotency",
        "priority_queue",
        "lease_and_restart_recovery",
        "retry_exhaustion",
        "blocked_task_isolation",
        "authenticated_internal_identity",
        "fail_closed_policy_guard",
        "financial_human_gate",
        "checkpoint_gate",
        "security_control_block",
        "oss_donor_adapter_boundary",
        "hash_chained_audit_ledger",
        "audit_tamper_detection",
        "mission_proven_acceptance_gate",
    ],
    "result": "PHASE2_PROVEN" if not failures else "PHASE2_FAILED",
    "scope_note": "PHASE2_PROVEN prova a Fundação Soberana; não é MISSION_PROVEN do produto completo.",
}
evidence_dir = ROOT / "evidence"
evidence_dir.mkdir(exist_ok=True)
(evidence_dir / "phase2-validation.json").write_text(
    json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
    encoding="utf-8",
)
(ROOT / "PHASE2_STATUS.md").write_text(
    "# Fase 2 — Fundação Soberana\n\n"
    + ("**Estado: PHASE2_PROVEN**\n" if not failures else "**Estado: PHASE2_FAILED**\n")
    + f"\nChecks: {evidence['summary']['passed']}/{evidence['summary']['total']} aprovados.\n"
    + "\nCapacidades: motor durável, estado SQLite, PolicyGuard executável, identidade interna e ledger de auditoria.\n"
    + "\nO produto completo permanece sem MISSION_PROVEN.\n",
    encoding="utf-8",
)

print(json.dumps(evidence["summary"], sort_keys=True))
if failures:
    print("FAILED:", ", ".join(failures))
    raise SystemExit(1)
print("PHASE2_PROVEN")
