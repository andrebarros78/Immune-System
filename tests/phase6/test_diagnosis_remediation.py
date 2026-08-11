from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from immune_core.audit import AuditLedger
from immune_core.checkpoints import CheckpointManager, WorkspaceManager
from immune_core.diagnosis import DiagnosisError, IncidentEngine, ProgressDetector
from immune_core.engine import DurableLoopEngine
from immune_core.execution import PrivilegedExecutor, SafeExecutor, WorkerManifest
from immune_core.identity import IdentityAuthority
from immune_core.observability import ObservabilityStore, SignalProcessor
from immune_core.policy import PolicyGuard
from immune_core.privilege import PrivilegeAuthority
from immune_core.remediation import CorrectionLab, RemediationError, RemediationPlanner, ValidationEngine
from immune_core.storage import SQLiteStateStore
from immune_core.workers import WorkerRunner


ROOT = Path(__file__).resolve().parents[2]
NOW = 2_000_100_000


class Phase6Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = SQLiteStateStore(root / "state.db")
        self.audit = AuditLedger(self.store)
        self.obs = ObservabilityStore(self.store, self.audit)
        self.signals = SignalProcessor(self.obs)
        self.incidents = IncidentEngine(self.store, self.obs, self.audit)
        self.progress = ProgressDetector(self.store)
        self.planner = RemediationPlanner(self.store, self.incidents, self.obs, self.audit)
        self.identities = IdentityAuthority(b"I" * 32)
        self.policy = PolicyGuard.from_repository(ROOT, self.identities, self.audit)
        self.engine = DurableLoopEngine(self.store, self.audit)
        self.workspaces = WorkspaceManager(root / "workspaces")
        self.checkpoints = CheckpointManager(root / "checkpoints", self.workspaces, self.audit)
        self.privileges = PrivilegeAuthority(b"P" * 32, self.identities, self.store, self.audit)
        self.safe = SafeExecutor(self.store, self.audit, self.policy, self.workspaces, self.checkpoints)
        self.privileged = PrivilegedExecutor(self.store, self.audit, self.policy, self.workspaces, self.checkpoints)
        self.runner = WorkerRunner(self.engine, self.safe, self.privileged, self.workspaces, self.checkpoints, self.privileges)
        self.lab = CorrectionLab(self.store, self.planner, self.incidents, self.engine, self.policy, self.workspaces, self.checkpoints, self.audit)
        self.validator = ValidationEngine(self.store, self.planner, self.incidents, self.obs, self.workspaces, self.checkpoints, self.audit)
        self.controller = self.identities.issue("controller", "controller", ("remediation:authorize",), ttl_seconds=600, now=NOW)
        self.worker = self.identities.issue("worker", "worker", ("execute:safe",), ttl_seconds=600, now=NOW)
        self.pyexe = str(Path(sys.executable).resolve())
        self.manifest = WorkerManifest("worker", ("command",), ("write",), "task-scoped", (Path(self.pyexe).name,))
        self.engine.create_mission("m", "system")
        self.engine.transition_mission("m", "AUTHORIZED", "test")
        self.engine.transition_mission("m", "RUNNING", "test")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _incident(self):
        signal = self.signals.ingest("sensor", {"kind": "health", "subject": "service:a", "severity": "error", "attributes": {"incident_key": "svc-a", "status": "down"}}, ts=NOW)
        return self.incidents.create_or_attach_from_signal(signal.signal.id, "m", title="service unavailable", now=NOW)

    def _confirmed_root(self):
        incident = self._incident()
        root = self.incidents.add_hypothesis(incident.id, "configuration drift", now=NOW)
        alt = self.incidents.add_hypothesis(incident.id, "network outage", now=NOW)
        ev1 = self.obs.evidence(kind="diagnostic", payload={"config_hash": "bad", "expected": "good"}, mission_id="m", ts=NOW + 1)
        ev2 = self.obs.evidence(kind="diagnostic", payload={"network": "reachable"}, mission_id="m", ts=NOW + 2)
        self.incidents.link_evidence(root.id, ev1.id, polarity="support", kind="configuration_diff", now=NOW + 3)
        self.incidents.link_evidence(alt.id, ev2.id, polarity="refute", kind="network_probe", now=NOW + 4)
        t1 = self.obs.evidence(kind="test", payload={"controlled_config_test": "reproduced"}, mission_id="m", ts=NOW + 5)
        t2 = self.obs.evidence(kind="test", payload={"network_isolation": "healthy"}, mission_id="m", ts=NOW + 6)
        self.incidents.record_attempt(incident.id, root.id, strategy="controlled_reproduction", test_name="apply_bad_config_in_lab", outcome="SUPPORTED", progress_score=1.0, evidence_id=t1.id, now=NOW + 7)
        self.incidents.record_attempt(incident.id, alt.id, strategy="dependency_isolation", test_name="network_probe", outcome="REFUTED", progress_score=1.0, evidence_id=t2.id, now=NOW + 8)
        self.incidents.confirm_root_cause(incident.id, root.id, now=NOW + 9)
        return incident.id, root.id

    def test_signal_creates_and_correlates_incident(self):
        first = self._incident()
        signal = self.signals.ingest("sensor2", {"kind": "health", "subject": "service:a", "severity": "critical", "attributes": {"incident_key": "svc-a", "status": "still-down"}}, ts=NOW + 1)
        second = self.incidents.create_or_attach_from_signal(signal.signal.id, "m", now=NOW + 1)
        self.assertEqual(first.id, second.id)
        count = self.store.conn.execute("SELECT COUNT(*) FROM diag_incident_signals WHERE incident_id=?", (first.id,)).fetchone()[0]
        self.assertEqual(2, count)

    def test_tampered_evidence_is_rejected(self):
        incident = self._incident()
        hypothesis = self.incidents.add_hypothesis(incident.id, "candidate", now=NOW)
        evidence = self.obs.evidence(kind="diagnostic", payload={"x": 1}, mission_id="m", ts=NOW)
        self.store.conn.execute("UPDATE obs_evidence SET payload_json='{}' WHERE id=?", (evidence.id,))
        with self.assertRaises(DiagnosisError):
            self.incidents.link_evidence(hypothesis.id, evidence.id, polarity="support")

    def test_symptom_disappearance_is_not_root_cause_proof(self):
        incident = self._incident()
        hypothesis = self.incidents.add_hypothesis(incident.id, "restart fixed symptom", now=NOW)
        evidence = self.obs.evidence(kind="diagnostic", payload={"symptom": "gone"}, mission_id="m", ts=NOW)
        test_evidence = self.obs.evidence(kind="test", payload={"after_restart": "healthy"}, mission_id="m", ts=NOW + 1)
        self.incidents.link_evidence(hypothesis.id, evidence.id, polarity="support", kind="symptom", now=NOW + 2)
        self.incidents.record_attempt(incident.id, hypothesis.id, strategy="restart", test_name="health_after_restart", outcome="SYMPTOM_DISAPPEARED", progress_score=1.0, evidence_id=test_evidence.id, now=NOW + 3)
        with self.assertRaises(DiagnosisError):
            self.incidents.confirm_root_cause(incident.id, hypothesis.id)

    def test_competing_hypothesis_must_be_discriminated(self):
        incident = self._incident()
        root = self.incidents.add_hypothesis(incident.id, "root", now=NOW)
        self.incidents.add_hypothesis(incident.id, "alternative", now=NOW)
        ev = self.obs.evidence(kind="diagnostic", payload={"root": True}, mission_id="m", ts=NOW)
        test_ev = self.obs.evidence(kind="test", payload={"root": "supported"}, mission_id="m", ts=NOW + 1)
        self.incidents.link_evidence(root.id, ev.id, polarity="support", now=NOW + 2)
        self.incidents.record_attempt(incident.id, root.id, strategy="counterfactual", test_name="root-test", outcome="SUPPORTED", progress_score=1, evidence_id=test_ev.id, now=NOW + 3)
        with self.assertRaises(DiagnosisError):
            self.incidents.confirm_root_cause(incident.id, root.id)

    def test_root_cause_requires_discriminating_evidence(self):
        incident_id, root_id = self._confirmed_root()
        incident = self.incidents.incident(incident_id)
        self.assertEqual("ROOT_CAUSE_CONFIRMED", incident.state)
        self.assertEqual(root_id, incident.root_hypothesis_id)
        self.assertEqual("ROOT_CAUSE", self.incidents.hypothesis(root_id).state)

    def test_no_progress_loop_forces_strategy_change(self):
        incident = self._incident()
        hypothesis = self.incidents.add_hypothesis(incident.id, "candidate", now=NOW)
        for i in range(3):
            evidence = self.obs.evidence(kind="test", payload={"attempt": i, "result": "same"}, mission_id="m", ts=NOW + i)
            self.incidents.record_attempt(incident.id, hypothesis.id, strategy="restart", test_name="same-restart", outcome="NO_CHANGE", progress_score=0, evidence_id=evidence.id, now=NOW + i)
        self.assertEqual("STALLED", self.progress.status(incident.id)["state"])
        with self.assertRaises(DiagnosisError):
            self.progress.require_strategy_change(incident.id, strategy="restart", test_name="same-restart")
        suggested = self.progress.suggest_strategy(incident.id)
        self.assertNotEqual("restart", suggested)
        self.progress.require_strategy_change(incident.id, strategy=suggested, test_name="new-test")

    def test_correction_cannot_be_planned_without_root_cause(self):
        incident = self._incident()
        with self.assertRaises(RemediationError):
            self.planner.plan(incident.id, description="fix", task_kind="command", argv=[self.pyexe, "-c", "pass"], validation={"expected_files": {"x": "y"}})

    def test_financial_correction_is_blocked_before_queue(self):
        incident_id, _ = self._confirmed_root()
        correction = self.planner.plan(incident_id, description="paid fix", task_kind="command", argv=[self.pyexe, "-c", "pass"], validation={"expected_files": {"x": "y"}}, risk={"purchase": True}, now=NOW + 10)
        with self.assertRaises(RemediationError):
            self.lab.queue(correction.id, self.controller, now=NOW + 11)
        self.assertEqual("PLANNED", self.planner.get(correction.id).state)

    def test_valid_correction_runs_through_worker_and_resolves(self):
        incident_id, _ = self._confirmed_root()
        correction = self.planner.plan(incident_id, description="repair configuration", task_kind="command", argv=[self.pyexe, "-c", "from pathlib import Path; Path('fixed.txt').write_text('good')"], validation={"expected_files": {"fixed.txt": "good"}, "audit_chain_required": True}, now=NOW + 10)
        queued = self.lab.queue(correction.id, self.controller, now=NOW + 11)
        self.assertTrue(queued.checkpoint_id)
        workspace = self.workspaces.for_task("m", queued.task_id)
        self.assertFalse((workspace / "fixed.txt").exists())
        outcome = self.runner.run_once(self.manifest, self.worker, now=NOW + 12)
        self.assertEqual("COMPLETED", outcome.state)
        result = self.validator.validate(correction.id, now=NOW + 13)
        self.assertTrue(result.passed)
        self.assertFalse(result.rolled_back)
        self.validator.finalize_incident(correction.id, result, recovery_verified=True, regression_verified=True, now=NOW + 14)
        self.assertEqual("RESOLVED", self.incidents.incident(incident_id).state)
        self.assertEqual("ACCEPTED", self.planner.get(correction.id).state)

    def test_successful_process_with_invalid_effect_is_rolled_back(self):
        incident_id, _ = self._confirmed_root()
        correction = self.planner.plan(incident_id, description="bad semantic correction", task_kind="command", argv=[self.pyexe, "-c", "from pathlib import Path; Path('state.txt').write_text('wrong')"], validation={"expected_files": {"state.txt": "right"}}, now=NOW + 10)
        queued = self.lab.queue(correction.id, self.controller, now=NOW + 11)
        workspace = self.workspaces.for_task("m", queued.task_id)
        outcome = self.runner.run_once(self.manifest, self.worker, now=NOW + 12)
        self.assertEqual("COMPLETED", outcome.state)
        self.assertTrue((workspace / "state.txt").exists())
        result = self.validator.validate(correction.id, now=NOW + 13)
        self.assertFalse(result.passed)
        self.assertTrue(result.rolled_back)
        self.assertFalse((workspace / "state.txt").exists())
        self.assertEqual("ROLLED_BACK", self.planner.get(correction.id).state)
        self.assertEqual("INVESTIGATING", self.incidents.incident(incident_id).state)

    def test_failed_process_is_not_accepted(self):
        incident_id, _ = self._confirmed_root()
        correction = self.planner.plan(incident_id, description="failing correction", task_kind="command", argv=[self.pyexe, "-c", "from pathlib import Path; Path('bad.txt').write_text('bad'); raise SystemExit(9)"], validation={"expected_files": {"bad.txt": "good"}}, now=NOW + 10)
        queued = self.lab.queue(correction.id, self.controller, now=NOW + 11)
        workspace = self.workspaces.for_task("m", queued.task_id)
        outcome = self.runner.run_once(self.manifest, self.worker, now=NOW + 12)
        self.assertEqual("FAILED", outcome.state)
        self.assertTrue(outcome.rolled_back)
        self.assertFalse((workspace / "bad.txt").exists())
        result = self.validator.validate(correction.id, now=NOW + 13)
        self.assertFalse(result.passed)
        with self.assertRaises(RemediationError):
            self.validator.finalize_incident(correction.id, result, recovery_verified=True, regression_verified=True)

    def test_resolution_requires_recovery_and_regression(self):
        incident_id, _ = self._confirmed_root()
        correction = self.planner.plan(incident_id, description="repair", task_kind="command", argv=[self.pyexe, "-c", "from pathlib import Path; Path('ok').write_text('1')"], validation={"expected_files": {"ok": "1"}}, now=NOW + 10)
        self.lab.queue(correction.id, self.controller, now=NOW + 11)
        self.runner.run_once(self.manifest, self.worker, now=NOW + 12)
        result = self.validator.validate(correction.id, now=NOW + 13)
        with self.assertRaises(DiagnosisError):
            self.validator.finalize_incident(correction.id, result, recovery_verified=False, regression_verified=True, now=NOW + 14)
        self.assertEqual("VALIDATING", self.incidents.incident(incident_id).state)

    def test_audit_chain_remains_valid(self):
        self._confirmed_root()
        valid, bad_seq = self.audit.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(bad_seq)


if __name__ == "__main__":
    unittest.main()
