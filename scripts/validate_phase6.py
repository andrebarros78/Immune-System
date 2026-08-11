#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.audit import AuditLedger
from immune_core.checkpoints import CheckpointManager, WorkspaceManager
from immune_core.diagnosis import DiagnosisError, IncidentEngine, ProgressDetector
from immune_core.engine import DurableLoopEngine
from immune_core.execution import PrivilegedExecutor, SafeExecutor, WorkerManifest
from immune_core.identity import IdentityAuthority
from immune_core.observability import ObservabilityStore, SignalProcessor
from immune_core.policy import PolicyGuard
from immune_core.privilege import PrivilegeAuthority
from immune_core.remediation import CorrectionLab, RemediationPlanner, ValidationEngine
from immune_core.storage import SQLiteStateStore
from immune_core.workers import WorkerRunner

NOW = 2_000_200_000
checks: list[dict] = []
failures: list[str] = []


def ok(name: str, condition: object, detail: str = "") -> None:
    passed = bool(condition)
    checks.append({"name": name, "passed": passed, "detail": str(detail)})
    if not passed:
        failures.append(name)


for phase in range(1, 6):
    status = ROOT / f"PHASE{phase}_STATUS.md"
    ok(f"phase{phase}_baseline_proven", status.is_file() and f"PHASE{phase}_PROVEN" in status.read_text(encoding="utf-8"))

required = [
    "immune_core/diagnosis.py",
    "immune_core/remediation.py",
    "tests/phase6/test_diagnosis_remediation.py",
    "scripts/validate_phase6.py",
    "adr/ADR-0006-diagnosis-remediation.md",
    ".github/workflows/phase6-diagnosis.yml",
]
for rel in required:
    ok(f"artifact:{rel}", (ROOT / rel).is_file())

for rel in ("immune_core/diagnosis.py", "immune_core/remediation.py"):
    text = (ROOT / rel).read_text(encoding="utf-8")
    try:
        ast.parse(text)
        ok(f"ast:{rel}", True)
    except SyntaxError as exc:
        ok(f"ast:{rel}", False, exc)

diagnosis_text = (ROOT / "immune_core/diagnosis.py").read_text(encoding="utf-8")
remediation_text = (ROOT / "immune_core/remediation.py").read_text(encoding="utf-8")
ok("diagnosis_no_direct_execution", "subprocess" not in diagnosis_text)
ok("remediation_no_direct_execution", "subprocess" not in remediation_text)
ok("root_cause_requires_support", "root cause requires net supporting evidence" in diagnosis_text)
ok("root_cause_requires_discriminating_test", "root cause requires a positive discriminating test" in diagnosis_text)
ok("competing_hypothesis_gate", "competing hypothesis has not been discriminated" in diagnosis_text)
ok("symptom_disappearance_not_positive_gate", "SYMPTOM_DISAPPEARED" not in diagnosis_text.split("def confirm_root_cause", 1)[1].split("def set_incident_state", 1)[0])
ok("progress_stall_detection", "same strategy repeated without measurable progress" in diagnosis_text)
ok("progress_forces_change", "stalled loop requires a different diagnostic strategy" in diagnosis_text)
ok("remediation_policy_guard_bridge", "self.policy.evaluate_token" in remediation_text)
ok("remediation_durable_queue", "self.engine.submit_task" in remediation_text)
ok("pre_execution_checkpoint", "self.checkpoints.create" in remediation_text)
ok("post_validation_rollback", "self.checkpoints.restore" in remediation_text)
ok("resolution_requires_recovery_regression", "recovery and regression validation are mandatory" in diagnosis_text)

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    store = SQLiteStateStore(root / "state.db")
    audit = AuditLedger(store)
    obs = ObservabilityStore(store, audit)
    signals = SignalProcessor(obs)
    incidents = IncidentEngine(store, obs, audit)
    progress = ProgressDetector(store)
    planner = RemediationPlanner(store, incidents, obs, audit)
    identities = IdentityAuthority(b"I" * 32)
    policy = PolicyGuard.from_repository(ROOT, identities, audit)
    engine = DurableLoopEngine(store, audit)
    workspaces = WorkspaceManager(root / "workspaces")
    checkpoints = CheckpointManager(root / "checkpoints", workspaces, audit)
    privileges = PrivilegeAuthority(b"P" * 32, identities, store, audit)
    safe = SafeExecutor(store, audit, policy, workspaces, checkpoints)
    privileged = PrivilegedExecutor(store, audit, policy, workspaces, checkpoints)
    runner = WorkerRunner(engine, safe, privileged, workspaces, checkpoints, privileges)
    lab = CorrectionLab(store, planner, incidents, engine, policy, workspaces, checkpoints, audit)
    validator = ValidationEngine(store, planner, incidents, obs, workspaces, checkpoints, audit)
    controller = identities.issue("proof-controller", "controller", ("remediation:authorize",), ttl_seconds=600, now=NOW)
    worker = identities.issue("proof-worker", "worker", ("execute:safe",), ttl_seconds=600, now=NOW)
    pyexe = str(Path(sys.executable).resolve())
    manifest = WorkerManifest("proof-worker", ("command",), ("write",), "task-scoped", (Path(pyexe).name,))
    engine.create_mission("m", "system")
    engine.transition_mission("m", "AUTHORIZED", "proof")
    engine.transition_mission("m", "RUNNING", "proof")

    signal = signals.ingest("health-sensor", {"kind": "health", "subject": "service:proof", "severity": "error", "attributes": {"incident_key": "proof", "state": "down"}}, ts=NOW)
    incident = incidents.create_or_attach_from_signal(signal.signal.id, "m", title="proof failure", now=NOW)
    ok("e2e_incident_created", incident.state == "INVESTIGATING")
    root_h = incidents.add_hypothesis(incident.id, "configuration drift", now=NOW)
    alt_h = incidents.add_hypothesis(incident.id, "network outage", now=NOW)
    ev_root = obs.evidence(kind="diagnostic", payload={"configuration": "drifted"}, mission_id="m", ts=NOW + 1)
    ev_alt = obs.evidence(kind="diagnostic", payload={"network": "healthy"}, mission_id="m", ts=NOW + 2)
    incidents.link_evidence(root_h.id, ev_root.id, polarity="support", kind="configuration_diff", now=NOW + 3)
    incidents.link_evidence(alt_h.id, ev_alt.id, polarity="refute", kind="network_probe", now=NOW + 4)
    test_root = obs.evidence(kind="test", payload={"controlled_reproduction": True}, mission_id="m", ts=NOW + 5)
    test_alt = obs.evidence(kind="test", payload={"network_isolated": True}, mission_id="m", ts=NOW + 6)
    incidents.record_attempt(incident.id, root_h.id, strategy="controlled_reproduction", test_name="config-repro", outcome="SUPPORTED", progress_score=1.0, evidence_id=test_root.id, now=NOW + 7)
    incidents.record_attempt(incident.id, alt_h.id, strategy="dependency_isolation", test_name="network-isolation", outcome="REFUTED", progress_score=1.0, evidence_id=test_alt.id, now=NOW + 8)
    confirmed = incidents.confirm_root_cause(incident.id, root_h.id, now=NOW + 9)
    ok("e2e_root_cause_confirmed", confirmed.state == "ROOT_CAUSE" and incidents.incident(incident.id).state == "ROOT_CAUSE_CONFIRMED")

    # Prove no-progress strategy detection independently.
    signal2 = signals.ingest("health-sensor", {"kind": "health", "subject": "service:loop", "severity": "warning", "attributes": {"incident_key": "loop"}}, ts=NOW + 10)
    stalled_incident = incidents.create_or_attach_from_signal(signal2.signal.id, "m", now=NOW + 10)
    stalled_h = incidents.add_hypothesis(stalled_incident.id, "unknown", now=NOW + 10)
    for i in range(3):
        ev = obs.evidence(kind="test", payload={"iteration": i, "change": False}, mission_id="m", ts=NOW + 11 + i)
        incidents.record_attempt(stalled_incident.id, stalled_h.id, strategy="restart", test_name="repeat", outcome="NO_CHANGE", progress_score=0, evidence_id=ev.id, now=NOW + 11 + i)
    ok("e2e_stalled_loop_detected", progress.status(stalled_incident.id)["state"] == "STALLED")
    blocked_repeat = False
    try:
        progress.require_strategy_change(stalled_incident.id, strategy="restart", test_name="repeat")
    except DiagnosisError:
        blocked_repeat = True
    ok("e2e_same_strategy_blocked", blocked_repeat)

    # Valid correction: policy -> durable queue -> checkpoint -> Worker -> validation -> resolution.
    correction = planner.plan(incident.id, description="restore configuration", task_kind="command", argv=[pyexe, "-c", "from pathlib import Path; Path('config.txt').write_text('healthy')"], validation={"expected_files": {"config.txt": "healthy"}, "audit_chain_required": True}, now=NOW + 20)
    queued = lab.queue(correction.id, controller, now=NOW + 21)
    ok("e2e_checkpoint_before_effect", bool(queued.checkpoint_id))
    workspace = workspaces.for_task("m", queued.task_id)
    ok("e2e_no_effect_before_worker", not (workspace / "config.txt").exists())
    outcome = runner.run_once(manifest, worker, now=NOW + 22)
    ok("e2e_worker_completed_correction", outcome.state == "COMPLETED")
    validation = validator.validate(correction.id, now=NOW + 23)
    ok("e2e_validation_passed", validation.passed and not validation.rolled_back)
    validator.finalize_incident(correction.id, validation, recovery_verified=True, regression_verified=True, now=NOW + 24)
    ok("e2e_incident_resolved_after_full_validation", incidents.incident(incident.id).state == "RESOLVED")

    # Semantic failure with exit 0 must still roll back.
    signal3 = signals.ingest("health-sensor", {"kind": "health", "subject": "service:rollback", "severity": "error", "attributes": {"incident_key": "rollback"}}, ts=NOW + 30)
    inc3 = incidents.create_or_attach_from_signal(signal3.signal.id, "m", now=NOW + 30)
    h3 = incidents.add_hypothesis(inc3.id, "bad setting", now=NOW + 30)
    e31 = obs.evidence(kind="diagnostic", payload={"setting": "bad"}, mission_id="m", ts=NOW + 31)
    e32 = obs.evidence(kind="test", payload={"reproduced": True}, mission_id="m", ts=NOW + 32)
    incidents.link_evidence(h3.id, e31.id, polarity="support", now=NOW + 33)
    incidents.record_attempt(inc3.id, h3.id, strategy="controlled_reproduction", test_name="setting-repro", outcome="SUPPORTED", progress_score=1, evidence_id=e32.id, now=NOW + 34)
    incidents.confirm_root_cause(inc3.id, h3.id, now=NOW + 35)
    bad = planner.plan(inc3.id, description="semantically wrong fix", task_kind="command", argv=[pyexe, "-c", "from pathlib import Path; Path('state.txt').write_text('wrong')"], validation={"expected_files": {"state.txt": "right"}}, now=NOW + 36)
    badq = lab.queue(bad.id, controller, now=NOW + 37)
    bad_ws = workspaces.for_task("m", badq.task_id)
    bad_outcome = runner.run_once(manifest, worker, now=NOW + 38)
    ok("e2e_bad_process_exits_zero", bad_outcome.state == "COMPLETED" and (bad_ws / "state.txt").exists())
    bad_validation = validator.validate(bad.id, now=NOW + 39)
    ok("e2e_semantic_failure_detected", not bad_validation.passed)
    ok("e2e_semantic_failure_rolled_back", bad_validation.rolled_back and not (bad_ws / "state.txt").exists())
    ok("e2e_failed_correction_not_resolved", incidents.incident(inc3.id).state == "INVESTIGATING")

    valid_chain, bad_seq = audit.verify_chain()
    ok("e2e_audit_chain_valid", valid_chain and bad_seq is None, bad_seq)
    store.close()

controlled = [
    "immune_core/diagnosis.py",
    "immune_core/remediation.py",
    "tests/phase6/test_diagnosis_remediation.py",
    "scripts/validate_phase6.py",
    "adr/ADR-0006-diagnosis-remediation.md",
    ".github/workflows/phase6-diagnosis.yml",
]
hashes = {rel: hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() for rel in controlled}
evidence = {
    "schema": 1,
    "phase": "PHASE_6_DIAGNOSIS_AND_REMEDIATION",
    "validated_at": datetime.now(timezone.utc).isoformat(),
    "checks": checks,
    "summary": {"total": len(checks), "passed": sum(1 for item in checks if item["passed"]), "failed": len(failures)},
    "controlled_file_sha256": hashes,
    "result": "PHASE6_PROVEN" if not failures else "PHASE6_FAILED",
    "scope_note": "PHASE6_PROVEN proves evidence-backed incident diagnosis, competing hypotheses, no-progress strategy change, policy-gated correction lab, validation and rollback. It is not MISSION_PROVEN for the complete product.",
}
path = ROOT / "evidence/phase6-validation.json"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
status = "PHASE6_PROVEN" if not failures else "PHASE6_FAILED"
(ROOT / "PHASE6_STATUS.md").write_text(
    "# Fase 6 — Diagnóstico e Correção\n\n"
    f"**Estado: {status}**\n\n"
    f"Checks: {evidence['summary']['passed']}/{evidence['summary']['total']} aprovados.\n\n"
    "Capacidades: incidentes correlacionados, hipóteses concorrentes, causalidade por evidência e teste discriminante, tentativas rastreadas, detecção de loop sem progresso, correção em laboratório, PolicyGuard, checkpoint, validação, regressão/recuperação e rollback semântico.\n\n"
    "O desaparecimento do sintoma não prova causa raiz; o produto completo permanece sem MISSION_PROVEN.\n",
    encoding="utf-8",
)
print(json.dumps(evidence["summary"], sort_keys=True))
if failures:
    print("FAILED:", ", ".join(failures))
    raise SystemExit(1)
print("PHASE6_PROVEN")
