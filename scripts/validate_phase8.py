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
from immune_core.diagnosis import IncidentEngine
from immune_core.engine import DurableLoopEngine
from immune_core.identity import IdentityAuthority
from immune_core.learning import ControlledLearningEngine, LearningError
from immune_core.observability import ObservabilityStore
from immune_core.remediation import RemediationPlanner
from immune_core.storage import SQLiteStateStore

NOW = 2_200_100_000
checks: list[dict] = []
failures: list[str] = []


def ok(name: str, condition: object, detail: str = "") -> None:
    passed = bool(condition)
    checks.append({"name": name, "passed": passed, "detail": str(detail)})
    if not passed:
        failures.append(name)


for phase in range(1, 8):
    path = ROOT / f"PHASE{phase}_STATUS.md"
    ok(f"phase{phase}_baseline_proven", path.is_file() and f"PHASE{phase}_PROVEN" in path.read_text(encoding="utf-8"))

required = [
    "immune_core/learning.py",
    "tests/phase8/test_controlled_learning.py",
    "adr/ADR-0008-controlled-learning.md",
    ".github/workflows/phase8-learning.yml",
]
for rel in required:
    ok(f"artifact:{rel}", (ROOT / rel).is_file())

learning_text = (ROOT / "immune_core/learning.py").read_text(encoding="utf-8")
try:
    ast.parse(learning_text)
    ok("ast:learning", True)
except SyntaxError as exc:
    ok("ast:learning", False, exc)

for token in ("QUARANTINED", "PROMOTED", "SUSPENDED", "RETIRED", "SUPERSEDED"):
    ok(f"state:{token}", token in learning_text)
ok("no_provider_authority", "providers" not in learning_text.lower() and "CognitiveCore" not in learning_text)
ok("no_subprocess", "subprocess" not in learning_text and "os.system" not in learning_text)
ok("no_eval_exec", "eval(" not in learning_text and "exec(" not in learning_text)
ok("confidence_is_computed", "(successes + 1.0) / (successes + failures + 2.0)" in learning_text)
ok("global_requires_distinct_systems", "successes < 2 or systems < 2" in learning_text)
ok("reviewer_promoter_separated", "reviewer and promoter must be different identities" in learning_text)
ok("accepted_correction_required", '!= "ACCEPTED"' in learning_text)
ok("resolved_incident_required", '!= "RESOLVED"' in learning_text)
ok("semantic_validation_required", 'int(validation["passed"]) != 1' in learning_text)
ok("skill_not_autoapproved", "resolve_approved" in learning_text and "skill:approve" not in learning_text)


def seed(store: SQLiteStateStore, obs: ObservabilityStore, mission_id: str, suffix: str, *, accepted: bool = True, passed: bool = True, rolled_back: bool = False):
    validation = {"expected_files": {"fixed.txt": "good"}}
    incident_id = f"inc-{suffix}"
    hypothesis_id = f"hyp-{suffix}"
    correction_id = f"corr-{suffix}"
    validation_id = f"val-{suffix}"
    ts = NOW + len(suffix)
    signal_ev = obs.evidence(kind="incident_signal", payload={"status": "down", "suffix": suffix}, mission_id=mission_id, ts=ts)
    attempt_ev = obs.evidence(kind="discriminating_test", payload={"root": "supported", "suffix": suffix}, mission_id=mission_id, ts=ts + 1)
    plan_ev = obs.evidence(kind="correction_plan", payload={"description": "repair configuration", "suffix": suffix}, mission_id=mission_id, ts=ts + 2)
    val_ev = obs.evidence(kind="remediation_validation", payload={"passed": passed, "rolled_back": rolled_back, "suffix": suffix}, mission_id=mission_id, ts=ts + 3)
    store.conn.execute("INSERT INTO diag_incidents(id,mission_id,correlation_key,title,state,root_hypothesis_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (incident_id, mission_id, suffix, "incident", "RESOLVED" if accepted else "INVESTIGATING", hypothesis_id if accepted else None, ts, ts + 4))
    store.conn.execute("INSERT INTO diag_hypotheses(id,incident_id,statement,state,confidence,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (hypothesis_id, incident_id, "configuration drift", "ROOT_CAUSE" if accepted else "SUPPORTED", 0.9, ts, ts + 1))
    store.conn.execute("INSERT INTO diag_incident_signals(incident_id,signal_id,evidence_id) VALUES(?,?,?)", (incident_id, f"signal-{suffix}", signal_ev.id))
    store.conn.execute("INSERT INTO diag_attempts(id,incident_id,hypothesis_id,strategy,test_name,outcome,progress_score,evidence_id,strategy_fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (f"attempt-{suffix}", incident_id, hypothesis_id, "controlled_reproduction", "config-diff", "SUPPORTED", 1.0, attempt_ev.id, f"fp-{suffix}", ts + 1))
    store.conn.execute("INSERT INTO diag_corrections(id,incident_id,mission_id,hypothesis_id,description,task_kind,argv_json,risk_json,validation_json,state,task_id,checkpoint_id,plan_evidence_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (correction_id, incident_id, mission_id, hypothesis_id, "repair configuration", "command", '["python","-c","pass"]', "{}", json.dumps(validation, sort_keys=True), "ACCEPTED" if accepted else ("ROLLED_BACK" if rolled_back else "PLANNED"), f"task-{suffix}", f"cp-{suffix}", plan_ev.id, ts + 2, ts + 4))
    store.conn.execute("INSERT INTO diag_validations(id,correction_id,passed,rolled_back,checks_json,evidence_id,created_at) VALUES(?,?,?,?,?,?,?)", (validation_id, correction_id, int(passed), int(rolled_back), "[]", val_ev.id, ts + 3))
    return correction_id, validation_id


with tempfile.TemporaryDirectory() as td:
    store = SQLiteStateStore(Path(td) / "state.db")
    audit = AuditLedger(store)
    obs = ObservabilityStore(store, audit)
    identity = IdentityAuthority(b"8" * 32)
    incidents = IncidentEngine(store, obs, audit)
    RemediationPlanner(store, incidents, obs, audit)
    engine = DurableLoopEngine(store, audit)
    for mission, system in (("m1", "system-a"), ("m2", "system-b"), ("m3", "system-c")):
        engine.create_mission(mission, system)
        engine.transition_mission(mission, "AUTHORIZED", "phase8")
        engine.transition_mission(mission, "RUNNING", "phase8")
    learning = ControlledLearningEngine(store, identity, obs, audit)
    registrar = identity.issue("registrar", "controller", ("knowledge:register",), ttl_seconds=600, now=NOW)
    validator = identity.issue("validator", "validator", ("knowledge:validate",), ttl_seconds=600, now=NOW)
    reviewer = identity.issue("reviewer", "validator", ("knowledge:review",), ttl_seconds=600, now=NOW)
    promoter = identity.issue("promoter", "controller", ("knowledge:promote",), ttl_seconds=600, now=NOW)

    c1, _ = seed(store, obs, "m1", "proof1")
    item = learning.create_candidate_from_correction(registrar, correction_id=c1, lineage_key="proof", kind="memory", content={"procedure": "repair configuration"}, target_scope="SYSTEM", now=NOW + 20)
    ok("runtime_candidate_quarantined", item.state == "QUARANTINED")
    ok("runtime_candidate_confidence_derived", item.confidence > 0.60)
    ok("runtime_provenance_correction", item.provenance["correction_id"] == c1)
    ok("runtime_provenance_evidence", len(item.provenance["evidence_ids"]) >= 4)
    blocked_without_review = False
    try:
        learning.promote(promoter, item.id, now=NOW + 21)
    except LearningError:
        blocked_without_review = True
    ok("runtime_promotion_without_review_blocked", blocked_without_review)
    learning.review_integrity(reviewer, item.id, now=NOW + 22)
    promoted = learning.promote(promoter, item.id, now=NOW + 23)
    ok("runtime_system_promoted", promoted.state == "PROMOTED")
    ok("runtime_system_recall", [x.id for x in learning.recall_promoted(system_id="system-a")] == [item.id])
    ok("runtime_scope_isolation", learning.recall_promoted(system_id="system-b") == [])

    g1, _ = seed(store, obs, "m1", "global1")
    global_item = learning.create_candidate_from_correction(registrar, correction_id=g1, lineage_key="global-proof", kind="runbook", content={"steps": ["repair configuration"]}, target_scope="GLOBAL", now=NOW + 30)
    learning.review_integrity(reviewer, global_item.id, now=NOW + 31)
    global_early_block = False
    try:
        learning.promote(promoter, global_item.id, now=NOW + 32)
    except LearningError:
        global_early_block = True
    ok("runtime_global_early_blocked", global_early_block)
    g2, _ = seed(store, obs, "m2", "global2")
    learning.add_reproduction_from_correction(validator, global_item.id, g2, now=NOW + 33)
    learning.review_integrity(reviewer, global_item.id, now=NOW + 34)
    global_promoted = learning.promote(promoter, global_item.id, now=NOW + 35)
    ok("runtime_global_promoted", global_promoted.state == "PROMOTED")
    ok("runtime_global_confidence", global_promoted.confidence >= 0.70)
    ok("runtime_global_visible_elsewhere", [x.id for x in learning.recall_promoted(system_id="system-c", kind="runbook")] == [global_item.id])

    _, bad1 = seed(store, obs, "m2", "bad1", accepted=False, passed=False, rolled_back=True)
    before = promoted.confidence
    suspended = learning.record_regression_from_validation(reviewer, item.id, bad1, now=NOW + 40)
    ok("runtime_regression_suspends", suspended.state == "SUSPENDED")
    ok("runtime_regression_reduces_confidence", suspended.confidence < before)
    ok("runtime_suspended_not_recalled", learning.recall_promoted(system_id="system-a", kind="memory") == [])
    _, bad2 = seed(store, obs, "m3", "bad2", accepted=False, passed=False, rolled_back=True)
    retired = learning.record_regression_from_validation(reviewer, item.id, bad2, now=NOW + 41)
    ok("runtime_two_regressions_retire", retired.state == "RETIRED")
    prov = learning.provenance(item.id)
    ok("runtime_outcomes_auditable", len(prov["outcomes"]) == 3)
    ok("runtime_reviews_auditable", len(prov["reviews"]) >= 3)
    valid, bad_seq = audit.verify_chain()
    ok("runtime_audit_chain_valid", valid and bad_seq is None, str(bad_seq))
    store.close()

controlled = required
hashes = {rel: hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() for rel in controlled}
evidence = {
    "schema": 1,
    "phase": "PHASE_8_CONTROLLED_LEARNING",
    "validated_at": datetime.now(timezone.utc).isoformat(),
    "checks": checks,
    "summary": {"total": len(checks), "passed": sum(1 for item in checks if item["passed"]), "failed": len(failures)},
    "controlled_file_sha256": hashes,
    "result": "PHASE8_PROVEN" if not failures else "PHASE8_FAILED",
    "scope_note": "PHASE8_PROVEN proves evidence-derived quarantine, confidence, independent review/promotion, scoped generalization, regression-driven suspension/retirement and versioned recall. It is not MISSION_PROVEN for the complete product.",
}
(ROOT / "evidence").mkdir(exist_ok=True)
(ROOT / "evidence/phase8-validation.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
status = "PHASE8_PROVEN" if not failures else "PHASE8_FAILED"
(ROOT / "PHASE8_STATUS.md").write_text(
    "# Fase 8 — Aprendizagem Controlada\n\n"
    f"**Estado: {status}**\n\n"
    f"Checks: {evidence['summary']['passed']}/{evidence['summary']['total']} aprovados.\n\n"
    "Capacidades: quarentena, proveniência causal, confiança derivada, reprodução multi-sistema, revisão independente, promoção versionada, suspensão por regressão, retirada e recall somente de conhecimento promovido.\n\n"
    "IA e Skills não recebem autoridade para declarar verdade; o produto completo permanece sem MISSION_PROVEN.\n",
    encoding="utf-8",
)
print(json.dumps(evidence["summary"], sort_keys=True))
if failures:
    print("FAILED:", ", ".join(failures))
    raise SystemExit(1)
print("PHASE8_PROVEN")
