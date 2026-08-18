from __future__ import annotations

import json
import os
import signal
import socket
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

from immune_core.audit import AuditLedger
from immune_core.checkpoints import CheckpointManager, WorkspaceManager
from immune_core.diagnosis import DiagnosisError, IncidentEngine, ProgressDetector
from immune_core.discovery import DiscoveryEngine, DonorSensorAdapter, PathSensor
from immune_core.engine import DurableLoopEngine
from immune_core.execution import WorkerManifest
from immune_execution_broker.execution import PrivilegedExecutor, SafeExecutor
from immune_core.identity import IdentityAuthority
from immune_core.observability import AnomalyDetector, ObservabilityStore, SignalProcessor
from immune_core.operator_dispatch import ControlledAction, OperatorCommandDispatcher, RunbookActionRegistry
from immune_core.operations import CommandGateway, OperationalStore, ReadModel, ReportBuilder
from immune_core.policy import PolicyGuard
from immune_core.privilege import PrivilegeAuthority
from immune_core.providers import ProviderManager, ProviderProtocolError, ProviderRequest, ProviderUnavailable, proposal_from_mapping
from immune_core.remediation import CorrectionLab, RemediationPlanner, ValidationEngine
from immune_core.runbooks import RunbookRunner
from immune_core.skills import SkillRegistry
from immune_core.state_backup import StateBackupManager
from immune_core.storage import SQLiteStateStore
from immune_execution_broker.workers import WorkerRunner
from immune_lab.admission import REQUIRED_EVIDENCE, evaluate_donor
from immune_gateway.adapters import TCPHealthGatewayAdapter
from immune_gateway.ingress import GatewayIngress
from immune_gateway.runtime_config import GatewayRuntimeConfig


ROOT = Path(__file__).resolve().parents[2]
NOW = 2_200_000_000
PHASE9_METRICS: dict[str, object] = {}


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    idx = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * q))))
    return ordered[idx]


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def tcp_reachable(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=0.2):
            return True
    except OSError:
        return False


class DownProvider:
    provider_id = "down-provider"
    locality = "external"
    cost_per_call = 0.0

    def propose(self, request, *, timeout_seconds):
        raise ProviderUnavailable("controlled outage")


class Phase9ProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = SQLiteStateStore(self.root / "state.db")
        self.audit = AuditLedger(self.store)
        self.identity = IdentityAuthority(b"9" * 32)
        self.policy = PolicyGuard.from_repository(ROOT, self.identity, self.audit)
        self.engine = DurableLoopEngine(self.store, self.audit)
        self.obs = ObservabilityStore(self.store, self.audit)
        self.signals = SignalProcessor(self.obs)
        self.incidents = IncidentEngine(self.store, self.obs, self.audit)
        self.progress = ProgressDetector(self.store)
        self.planner = RemediationPlanner(self.store, self.incidents, self.obs, self.audit)
        self.workspaces = WorkspaceManager(self.root / "workspaces")
        self.checkpoints = CheckpointManager(self.root / "checkpoints", self.workspaces, self.audit)
        self.privileges = PrivilegeAuthority(b"P" * 32, self.identity, self.store, self.audit)
        self.safe = SafeExecutor(self.store, self.audit, self.policy, self.workspaces, self.checkpoints)
        self.privileged = PrivilegedExecutor(self.store, self.audit, self.policy, self.workspaces, self.checkpoints)
        self.runner = WorkerRunner(self.engine, self.safe, self.privileged, self.workspaces, self.checkpoints, self.privileges)
        self.ops = OperationalStore(self.store, self.audit).bind_identity(self.identity)
        self.read = ReadModel(self.store, freshness_seconds=60)
        self.gateway = CommandGateway(self.store, self.identity, self.policy, self.engine, self.audit)
        self.lab = CorrectionLab(self.store, self.planner, self.incidents, self.engine, self.policy, self.workspaces, self.checkpoints, self.audit)
        self.validator = ValidationEngine(self.store, self.planner, self.incidents, self.obs, self.workspaces, self.checkpoints, self.audit)
        self.pyexe = str(Path(sys.executable).resolve())
        self.worker_manifest = WorkerManifest("worker", ("command",), ("write",), "task-scoped", (Path(self.pyexe).name,), max_runtime_seconds=20)
        self.worker_token = self.identity.issue("worker", "worker", ("execute:safe",), ttl_seconds=1800, now=NOW)
        self.controller = self.identity.issue("controller", "controller", ("remediation:authorize",), ttl_seconds=1800, now=NOW)
        self.engine.create_mission("m", "system")
        self.engine.transition_mission("m", "AUTHORIZED", "phase9")
        self.engine.transition_mission("m", "RUNNING", "phase9")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _confirmed_root(self, suffix: str = "") -> tuple[str, str]:
        key = f"config{suffix}"
        signal_row = self.signals.ingest("sensor", {"kind": "health", "subject": f"service:{key}", "severity": "error", "attributes": {"incident_key": key, "status": "down"}}, ts=NOW + 1)
        incident = self.incidents.create_or_attach_from_signal(signal_row.signal.id, "m", title="controlled failure", now=NOW + 2)
        root = self.incidents.add_hypothesis(incident.id, "configuration drift", now=NOW + 3)
        alt = self.incidents.add_hypothesis(incident.id, "network outage", now=NOW + 3)
        ev1 = self.obs.evidence(kind="diagnostic", payload={"config": "bad"}, mission_id="m", ts=NOW + 4)
        ev2 = self.obs.evidence(kind="diagnostic", payload={"network": "reachable"}, mission_id="m", ts=NOW + 5)
        self.incidents.link_evidence(root.id, ev1.id, polarity="support", kind="configuration_diff", now=NOW + 6)
        self.incidents.link_evidence(alt.id, ev2.id, polarity="refute", kind="network_probe", now=NOW + 7)
        t1 = self.obs.evidence(kind="test", payload={"reproduced": True}, mission_id="m", ts=NOW + 8)
        t2 = self.obs.evidence(kind="test", payload={"network_healthy": True}, mission_id="m", ts=NOW + 9)
        self.incidents.record_attempt(incident.id, root.id, strategy="controlled_reproduction", test_name="config-reproduction", outcome="SUPPORTED", progress_score=1.0, evidence_id=t1.id, now=NOW + 10)
        self.incidents.record_attempt(incident.id, alt.id, strategy="dependency_isolation", test_name="network-probe", outcome="REFUTED", progress_score=1.0, evidence_id=t2.id, now=NOW + 11)
        self.incidents.confirm_root_cause(incident.id, root.id, now=NOW + 12)
        return incident.id, root.id

    def test_01_stopped_service_is_detected_and_recovered_by_authorized_runbook(self):
        port = free_tcp_port()
        pidfile = self.root / "service.pid"
        recovery = self.root / "recover_service.py"
        recovery.write_text("import subprocess,sys,pathlib\np=subprocess.Popen([sys.executable,'-m','http.server',sys.argv[1],'--bind','127.0.0.1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\npathlib.Path(sys.argv[2]).write_text(str(p.pid))\n", encoding="utf-8")
        gateway_cfg_path = self.root / "gateway-health.json"
        gateway_cfg_path.write_text(json.dumps({"schema":1,"owner_scope":"immune-gateway","bind":{"host":"127.0.0.1","port":4020},"limits":{},"systems":[{"id":"system","adapter":"tcp-health","enabled":True,"ingress":"pull","config":{}}]}), encoding="utf-8")
        gateway_cfg = GatewayRuntimeConfig.load(gateway_cfg_path)
        sensor = TCPHealthGatewayAdapter("system", "127.0.0.1", port, adapter_id="tcp-health")
        ingress = GatewayIngress(self.store, self.audit, gateway_cfg, {"system": sensor})
        before_receipt = ingress.collect_once("system", timeout_seconds=0.1, now=NOW + 20)
        before = self.store.conn.execute("SELECT attributes_json FROM obs_signals WHERE id=?", (before_receipt.signal_id,)).fetchone()
        self.assertIsNotNone(before)
        self.assertFalse(json.loads(before[0])["reachable"])

        registry = RunbookActionRegistry({("service-recovery", "demo"): ControlledAction("recover-demo", "command", (self.pyexe, str(recovery), str(port), str(pidfile)), False, 10)})
        operator = self.identity.issue("operator", "human", ("operator:diagnose",), ttl_seconds=600, now=NOW)
        RunbookRunner(self.gateway).execute("service-recovery", mission_id="m", operator_token=operator, parameters={"service": "demo"}, now=NOW + 21)
        dispatched = OperatorCommandDispatcher(self.store, self.engine, registry, self.audit).run_once(now=NOW + 22)
        self.assertEqual("DISPATCHED", dispatched.state)
        service_manifest = WorkerManifest("service-worker", ("command",), ("service-recovery",), "task-scoped", (Path(self.pyexe).name,))
        service_token = self.identity.issue("service-worker", "worker", ("execute:safe",), ttl_seconds=600, now=NOW)
        outcome = self.runner.run_once(service_manifest, service_token, now=NOW + 23)
        self.assertEqual("COMPLETED", outcome.state)
        deadline = time.time() + 3
        while time.time() < deadline and not tcp_reachable(port):
            time.sleep(0.05)
        try:
            self.assertTrue(tcp_reachable(port))
            after_receipt = ingress.collect_once("system", timeout_seconds=0.1, now=NOW + 24)
            after = self.store.conn.execute("SELECT attributes_json FROM obs_signals WHERE id=?", (after_receipt.signal_id,)).fetchone()
            self.assertTrue(json.loads(after[0])["reachable"])
        finally:
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), signal.SIGTERM)
                except (OSError, ValueError):
                    pass

    def test_02_configuration_root_cause_is_fixed_with_checkpoint_available(self):
        incident_id, _ = self._confirmed_root("-fix")
        correction = self.planner.plan(incident_id, description="repair configuration", task_kind="command", argv=[self.pyexe, "-c", "from pathlib import Path; Path('config.txt').write_text('good')"], validation={"expected_files": {"config.txt": "good"}, "audit_chain_required": True}, now=NOW + 30)
        queued = self.lab.queue(correction.id, self.controller, now=NOW + 31)
        self.assertIsNotNone(queued.checkpoint_id)
        self.assertTrue(self.checkpoints.verify(self.checkpoints.get(queued.checkpoint_id)))
        self.assertEqual("COMPLETED", self.runner.run_once(self.worker_manifest, self.worker_token, now=NOW + 32).state)
        result = self.validator.validate(correction.id, now=NOW + 33)
        self.assertTrue(result.passed)
        self.validator.finalize_incident(correction.id, result, recovery_verified=True, regression_verified=True, now=NOW + 34)
        self.assertEqual("RESOLVED", self.incidents.incident(incident_id).state)

    def test_03_correction_that_breaks_regression_is_rejected_and_rolled_back(self):
        incident_id, _ = self._confirmed_root("-regression")
        correction = self.planner.plan(incident_id, description="bad semantic fix", task_kind="command", argv=[self.pyexe, "-c", "from pathlib import Path; Path('state.txt').write_text('wrong')"], validation={"expected_files": {"state.txt": "right"}}, now=NOW + 40)
        queued = self.lab.queue(correction.id, self.controller, now=NOW + 41)
        self.assertEqual("COMPLETED", self.runner.run_once(self.worker_manifest, self.worker_token, now=NOW + 42).state)
        result = self.validator.validate(correction.id, now=NOW + 43)
        self.assertFalse(result.passed)
        self.assertTrue(result.rolled_back)
        workspace = self.workspaces.for_task("m", queued.task_id)
        self.assertFalse((workspace / "state.txt").exists())
        self.assertEqual("ROLLED_BACK", self.planner.get(correction.id).state)

    def test_04_invalid_deployment_process_is_automatically_reverted(self):
        incident_id, _ = self._confirmed_root("-deploy")
        correction = self.planner.plan(incident_id, description="invalid deployment", task_kind="command", argv=[self.pyexe, "-c", "from pathlib import Path; Path('deploy.txt').write_text('bad'); raise SystemExit(7)"], validation={"expected_files": {"deploy.txt": "good"}}, now=NOW + 50)
        queued = self.lab.queue(correction.id, self.controller, now=NOW + 51)
        result = self.runner.run_once(self.worker_manifest, self.worker_token, now=NOW + 52)
        self.assertEqual("FAILED", result.state)
        self.assertTrue(result.rolled_back)
        workspace = self.workspaces.for_task("m", queued.task_id)
        self.assertFalse((workspace / "deploy.txt").exists())

    def test_05_restart_resumes_expired_lease_without_duplicate_action(self):
        db = self.root / "restart.db"
        first = SQLiteStateStore(db)
        first_engine = DurableLoopEngine(first, AuditLedger(first))
        first_engine.create_mission("restart-m", "system")
        first_engine.transition_mission("restart-m", "AUTHORIZED", "test")
        first_engine.transition_mission("restart-m", "RUNNING", "test")
        task_id = first_engine.submit_task("restart-m", "proof", {"value": 1}, idempotency_key="restart-once", now=NOW)
        lease = first_engine.claim_next("crashed-worker", lease_seconds=1, now=NOW)
        self.assertEqual(task_id, lease.id)
        first.close()
        second = SQLiteStateStore(db)
        second_engine = DurableLoopEngine(second, AuditLedger(second))
        summary = second_engine.resume(now=NOW + 5)
        self.assertEqual(1, summary["recovered_leases"])
        same_id = second_engine.submit_task("restart-m", "proof", {"value": 999}, idempotency_key="restart-once", now=NOW + 5)
        self.assertEqual(task_id, same_id)
        lease2 = second_engine.claim_next("replacement-worker", now=NOW + 6)
        second_engine.complete_task(lease2, now=NOW + 7)
        self.assertEqual(1, len(second.list_tasks("restart-m")))
        self.assertEqual("COMPLETED", second.get_task(task_id)["state"])
        second.close()

    def test_06_blocked_incident_does_not_stop_another_system(self):
        self.engine.create_mission("blocked", "system-a")
        self.engine.transition_mission("blocked", "AUTHORIZED", "test")
        self.engine.transition_mission("blocked", "RUNNING", "test")
        self.engine.transition_mission("blocked", "BLOCKED", "controlled blocker")
        self.engine.create_mission("healthy", "system-b")
        self.engine.transition_mission("healthy", "AUTHORIZED", "test")
        self.engine.transition_mission("healthy", "RUNNING", "test")
        task = self.engine.submit_task("healthy", "command", {"mode": "safe", "argv": [self.pyexe, "-c", "from pathlib import Path; Path('alive.txt').write_text('ok')"], "material_change": True}, idempotency_key="healthy-continues", now=NOW + 60)
        outcome = self.runner.run_once(self.worker_manifest, self.worker_token, now=NOW + 61)
        self.assertEqual(task, outcome.task_id)
        self.assertEqual("COMPLETED", outcome.state)
        self.assertEqual("BLOCKED", self.store.get_mission("blocked")["state"])

    def test_07_monitoring_and_containment_continue_without_external_ai(self):
        manager = ProviderManager([DownProvider()], self.identity, self.audit)
        proposal = manager.propose(ProviderRequest("m", "diagnose controlled outage"), timeout_seconds=0.2, now=NOW + 70)
        self.assertTrue(proposal.degraded)
        self.assertEqual("DEGRADED_NO_AI", proposal.metadata["mode"])
        watched = self.root / "watched.txt"
        watched.write_text("healthy", encoding="utf-8")
        discovery = DiscoveryEngine((PathSensor("path", (watched,)),), self.obs, self.signals, AnomalyDetector(self.obs), audit=self.audit)
        cycle = discovery.run_cycle(mission_id="m", now=NOW + 71)
        self.assertEqual(1, cycle.sensors_ok)
        self.assertTrue(self.obs.verify_evidence(cycle.evidence_id))

    def test_08_unknown_technology_skill_is_quarantined_then_lab_approved(self):
        skills = SkillRegistry(self.store, self.identity, self.audit)
        donor = {"id": "unknown-tech", "purpose": "adapter for unknown technology", "resolved_commit": "abc123", "status": "collected"}
        register = self.identity.issue("registrar", "system", ("skill:register",), ttl_seconds=600, now=NOW)
        validate = self.identity.issue("validator", "system", ("skill:validate",), ttl_seconds=600, now=NOW)
        approve = self.identity.issue("approver", "system", ("skill:approve",), ttl_seconds=600, now=NOW)
        record = skills.register_donor_skill(register, skill_id="unknown-tech-skill", version="1.0.0", capability="unknown-tech", donor=donor, now=NOW + 80)
        self.assertEqual("QUARANTINED", record.state)
        for name in REQUIRED_EVIDENCE:
            skills.record_evidence(validate, skill_id=record.skill_id, version=record.version, evidence_name=name, passed=True, now=NOW + 81)
        approved = skills.approve(approve, skill_id=record.skill_id, version=record.version, now=NOW + 82)
        self.assertEqual("APPROVED", approved.state)
        self.assertEqual("adapter-only", approved.authority)
        self.assertFalse(approved.executable)

    def test_09_worker_exceeding_contract_scope_is_blocked(self):
        self.engine.submit_task("m", "admin-command", {"mode": "safe", "argv": [self.pyexe, "-c", "print('should-not-run')"]}, idempotency_key="scope-escape", now=NOW + 90)
        outcome = self.runner.run_once(self.worker_manifest, self.worker_token, now=NOW + 91)
        self.assertEqual("BLOCKED", outcome.state)
        self.assertIn("outside worker manifest", outcome.detail)

    def test_10_oss_piece_has_no_direct_authority(self):
        donor = {"id": "donor", "purpose": "sensor", "resolved_commit": "deadbeef", "status": "collected"}
        lab = evaluate_donor(donor, {name: True for name in REQUIRED_EVIDENCE})
        self.assertEqual("adapter-only", lab.authority)
        self.assertFalse(lab.executable)
        adapter = DonorSensorAdapter(lab, lambda: ())
        self.assertTrue(adapter.sensor_id.startswith("donor:"))
        malicious = SimpleNamespace(decision="approved", authority="direct", executable=True, donor_id="evil")
        with self.assertRaises(PermissionError):
            DonorSensorAdapter(malicious, lambda: ())

    def test_11_state_is_recovered_from_verified_backup(self):
        backups = StateBackupManager(self.store, self.root / "backups", self.audit)
        ref = backups.create(now=NOW + 100)
        self.assertTrue(backups.verify(ref))
        self.engine.create_mission("after-backup", "later")
        restored_path = backups.restore_to(ref, self.root / "restored.db", now=NOW + 101)
        restored = SQLiteStateStore(restored_path)
        try:
            self.assertIsNotNone(restored.get_mission("m"))
            self.assertIsNone(restored.get_mission("after-backup"))
        finally:
            restored.close()
        Path(ref.path).write_bytes(Path(ref.path).read_bytes() + b"tamper")
        self.assertFalse(backups.verify(ref))

    def test_12_load_and_concurrency_1_4_8_16_32_have_no_task_loss(self):
        db = self.root / "load.db"
        seed = SQLiteStateStore(db)
        seed_engine = DurableLoopEngine(seed, AuditLedger(seed))
        seed_engine.create_mission("load", "system")
        seed_engine.transition_mission("load", "AUTHORIZED", "load")
        seed_engine.transition_mission("load", "RUNNING", "load")
        seed.close()
        levels = [1, 4, 8, 16, 32]
        latencies: list[float] = []
        expected = 0

        def submit_one(batch: int, i: int) -> str:
            started = time.perf_counter()
            store = SQLiteStateStore(db)
            try:
                engine = DurableLoopEngine(store, AuditLedger(store))
                return engine.submit_task("load", "probe", {"batch": batch, "i": i}, idempotency_key=f"load:{batch}:{i}", now=NOW + batch)
            finally:
                latencies.append(time.perf_counter() - started)
                store.close()

        def consume_one(batch: int, i: int) -> str:
            started = time.perf_counter()
            store = SQLiteStateStore(db)
            try:
                engine = DurableLoopEngine(store, AuditLedger(store))
                lease = engine.claim_next(f"load-worker-{batch}-{i}", now=NOW + 1000 + batch)
                if lease is None:
                    return "IDLE"
                engine.complete_task(lease, now=NOW + 1001 + batch)
                return lease.id
            finally:
                latencies.append(time.perf_counter() - started)
                store.close()

        for batch, level in enumerate(levels, 1):
            with ThreadPoolExecutor(max_workers=level) as pool:
                ids = list(pool.map(lambda i: submit_one(batch, i), range(level)))
            self.assertEqual(level, len(set(ids)))
            expected += level
            with ThreadPoolExecutor(max_workers=level) as pool:
                consumed = list(pool.map(lambda i: consume_one(batch, i), range(level)))
            self.assertNotIn("IDLE", consumed)

        verify = SQLiteStateStore(db)
        try:
            rows = verify.list_tasks("load")
            self.assertEqual(expected, len(rows))
            self.assertTrue(all(row["state"] == "COMPLETED" for row in rows))
            valid, bad_seq = AuditLedger(verify).verify_chain()
            self.assertTrue(valid, bad_seq)
        finally:
            verify.close()
        metrics = {"levels": levels, "tasks": expected, "p50_seconds": percentile(latencies, 0.50), "p95_seconds": percentile(latencies, 0.95), "p99_seconds": percentile(latencies, 0.99)}
        PHASE9_METRICS["load"] = metrics
        self.assertLess(metrics["p99_seconds"], 10.0)

    def test_13_no_progress_is_detected_and_requires_new_strategy(self):
        incident_id, root_id = self._confirmed_root("-stalled")
        for i in range(3):
            ev = self.obs.evidence(kind="test", payload={"attempt": i, "same": True}, mission_id="m", ts=NOW + 110 + i)
            self.incidents.record_attempt(incident_id, root_id, strategy="restart", test_name="same-restart", outcome="NO_CHANGE", progress_score=0, evidence_id=ev.id, now=NOW + 110 + i)
        status = self.progress.status(incident_id)
        self.assertEqual("STALLED", status["state"])
        with self.assertRaises(DiagnosisError):
            self.progress.require_strategy_change(incident_id, strategy="restart", test_name="same-restart")
        different = self.progress.suggest_strategy(incident_id)
        self.assertNotEqual("restart", different)
        self.progress.require_strategy_change(incident_id, strategy=different, test_name="different-test")

    def test_14_human_intervention_occurs_for_real_exception_not_technical_block(self):
        self.engine.submit_task("m", "forbidden-kind", {"mode": "safe", "argv": [self.pyexe, "-c", "print(1)"]}, idempotency_key="technical-block", now=NOW + 120)
        blocked = self.runner.run_once(self.worker_manifest, self.worker_token, now=NOW + 121)
        self.assertEqual("BLOCKED", blocked.state)
        self.assertEqual([], self.read.human_exceptions())
        exception = self.ops.request_human_exception(mission_id="m", reason="MFA", required_action="Approve the MFA prompt", consequence="external operation remains blocked", continuation="resume the authorized mission", now=NOW + 122)
        self.assertEqual("PENDING", exception.state)
        self.assertEqual(1, len(self.read.human_exceptions(pending_only=True)))

    def test_15_report_links_requirement_action_test_and_evidence(self):
        signal_row = self.signals.ingest("report-sensor", {"kind": "service", "subject": "report-service", "severity": "error", "attributes": {"incident_key": "report"}}, ts=NOW + 130)
        incident = self.incidents.create_or_attach_from_signal(signal_row.signal.id, "m", now=NOW + 131)
        hypothesis = self.incidents.add_hypothesis(incident.id, "report hypothesis", now=NOW + 132)
        ev = self.obs.evidence(kind="test", payload={"result": "discriminating"}, mission_id="m", ts=NOW + 133)
        self.incidents.record_attempt(incident.id, hypothesis.id, strategy="isolate", test_name="report-discriminating-test", outcome="SUPPORTED", progress_score=1, evidence_id=ev.id, now=NOW + 134)
        report = ReportBuilder(self.store, self.audit).build_incident(incident.id, requirement_ids=("REQ-E2E-15",), now=NOW + 135)
        trace = report["content"]["traceability"][0]
        self.assertEqual("REQ-E2E-15", trace["requirement"])
        self.assertIn("report-discriminating-test", trace["actions"])
        self.assertIn(ev.id, trace["evidence_ids"])
        self.assertTrue(ReportBuilder(self.store, self.audit).verify(report["id"]))

    def test_16_security_boundaries_fail_closed(self):
        token = self.identity.issue("security-worker", "worker", ("execute:safe",), ttl_seconds=600, now=NOW)
        decision = self.policy.evaluate_token(token, {"mission_id": "m", "action": "disable-security", "required_scope": "execute:safe", "mission_authorized": True, "system_authorized": True, "scope_ok": True, "disables_security_control": True}, now=NOW + 140)
        self.assertEqual("BLOQUEAR", decision.decision)
        with self.assertRaises(ProviderProtocolError):
            proposal_from_mapping("malicious-ai", {"summary": "x", "hypotheses": [], "recommended_tasks": [], "confidence": 0, "execute": True})
        operator = self.identity.issue("operator", "human", ("operator:diagnose",), ttl_seconds=600, now=NOW)
        RunbookRunner(self.gateway).execute("service-recovery", mission_id="m", operator_token=operator, parameters={"service": "unregistered"}, now=NOW + 141)
        result = OperatorCommandDispatcher(self.store, self.engine, RunbookActionRegistry({}), self.audit).run_once(now=NOW + 142)
        self.assertEqual("BLOCKED", result.state)
        self.assertIsNone(result.child_task_id)

    def test_17_endurance_window_has_no_loss_and_audit_remains_valid(self):
        db = self.root / "endurance.db"
        store = SQLiteStateStore(db)
        audit = AuditLedger(store)
        engine = DurableLoopEngine(store, audit)
        engine.create_mission("endurance", "system")
        engine.transition_mission("endurance", "AUTHORIZED", "endurance")
        engine.transition_mission("endurance", "RUNNING", "endurance")
        started = time.perf_counter()
        cycles = 0
        failures = 0
        while time.perf_counter() - started < 2.0 or cycles < 128:
            try:
                tid = engine.submit_task("endurance", "probe", {"cycle": cycles}, idempotency_key=f"endurance:{cycles}")
                lease = engine.claim_next("endurance-worker")
                if lease is None or lease.id != tid:
                    failures += 1
                    break
                engine.complete_task(lease)
                cycles += 1
            except Exception:
                failures += 1
                break
        duration = time.perf_counter() - started
        valid, bad_seq = audit.verify_chain()
        rows = store.list_tasks("endurance")
        store.close()
        metrics = {"duration_seconds": duration, "cycles": cycles, "failures": failures}
        PHASE9_METRICS["endurance"] = metrics
        self.assertGreaterEqual(duration, 2.0)
        self.assertGreaterEqual(cycles, 128)
        self.assertEqual(0, failures)
        self.assertEqual(cycles, len(rows))
        self.assertTrue(all(row["state"] == "COMPLETED" for row in rows))
        self.assertTrue(valid, bad_seq)


if __name__ == "__main__":
    unittest.main()
