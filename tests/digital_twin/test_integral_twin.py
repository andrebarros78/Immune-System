from __future__ import annotations

import socket
import subprocess
import unittest
import urllib.request
from pathlib import Path

from immune_core.audit import AuditLedger
from immune_core.checkpoints import CheckpointManager, WorkspaceManager
from immune_core.continuous import ContinuousSupervisor
from immune_core.diagnosis import IncidentEngine
from immune_core.discovery import DiscoveryEngine
from immune_core.engine import DurableLoopEngine
from immune_core.identity import IdentityAuthority
from immune_core.learning import ControlledLearningEngine
from immune_core.observability import AnomalyDetector, ObservabilityStore, SignalProcessor
from immune_core.operations import OperationalStore, ReadModel
from immune_core.policy import PolicyGuard
from immune_core.providers import ProviderManager, ProviderRequest
from immune_core.remediation import CorrectionLab, RemediationPlanner, ValidationEngine
from immune_core.state_backup import StateBackupManager
from immune_core.storage import SQLiteStateStore
from immune_core.update_manager import ReleaseManager
from immune_core.watchdog import HeartbeatWatchdog
from immune_twin.sandbox import ClosedDigitalTwin, SandboxViolation, TwinActuator, TwinSensor


ROOT = Path(__file__).resolve().parents[2]
NOW = 2_100_000_000


class IntegralDigitalTwinTests(unittest.TestCase):
    def _core(self, twin: ClosedDigitalTwin):
        store = SQLiteStateStore(twin.path("state", "immune.sqlite3"))
        audit = AuditLedger(store)
        obs = ObservabilityStore(store, audit)
        processor = SignalProcessor(obs)
        incidents = IncidentEngine(store, obs, audit)
        identities = IdentityAuthority(b"T" * 32)
        policy = PolicyGuard.from_repository(ROOT, identities, audit)
        engine = DurableLoopEngine(store, audit)
        workspaces = WorkspaceManager(twin.path("workspaces"))
        checkpoints = CheckpointManager(twin.path("checkpoints"), workspaces, audit)
        planner = RemediationPlanner(store, incidents, obs, audit)
        lab = CorrectionLab(store, planner, incidents, engine, policy, workspaces, checkpoints, audit)
        validator = ValidationEngine(store, planner, incidents, obs, workspaces, checkpoints, audit)
        return store, audit, obs, processor, incidents, identities, policy, engine, workspaces, checkpoints, planner, lab, validator

    def _confirmed_root(self, twin, store, obs, processor, incidents):
        sensors = [TwinSensor(twin.world, "api"), TwinSensor(twin.world, "db")]
        discovery = DiscoveryEngine(sensors, obs, processor, AnomalyDetector(obs), audit=AuditLedger(store))
        cycle = discovery.run_cycle(mission_id="m", now=NOW)
        self.assertEqual(2, cycle.sensors_ok)
        row = store.conn.execute(
            "SELECT id FROM obs_signals WHERE subject='service:api' ORDER BY ts DESC LIMIT 1"
        ).fetchone()
        self.assertIsNotNone(row)
        incident = incidents.create_or_attach_from_signal(str(row["id"]), "m", title="virtual api unavailable", now=NOW + 1)
        root = incidents.add_hypothesis(incident.id, "configuration drift", now=NOW + 2)
        alt = incidents.add_hypothesis(incident.id, "database dependency outage", now=NOW + 2)
        ev1 = obs.evidence(kind="diagnostic", payload={"mode": "bad", "expected": "good"}, mission_id="m", ts=NOW + 3)
        ev2 = obs.evidence(kind="diagnostic", payload={"db": "healthy"}, mission_id="m", ts=NOW + 4)
        incidents.link_evidence(root.id, ev1.id, polarity="support", kind="config_delta", now=NOW + 5)
        incidents.link_evidence(alt.id, ev2.id, polarity="refute", kind="dependency_probe", now=NOW + 6)
        t1 = obs.evidence(kind="test", payload={"controlled_reproduction": "supported"}, mission_id="m", ts=NOW + 7)
        t2 = obs.evidence(kind="test", payload={"dependency_isolation": "refuted"}, mission_id="m", ts=NOW + 8)
        incidents.record_attempt(incident.id, root.id, strategy="controlled_reproduction", test_name="virtual-config-reproduction", outcome="SUPPORTED", progress_score=1.0, evidence_id=t1.id, now=NOW + 9)
        incidents.record_attempt(incident.id, alt.id, strategy="dependency_isolation", test_name="virtual-db-probe", outcome="REFUTED", progress_score=1.0, evidence_id=t2.id, now=NOW + 10)
        incidents.confirm_root_cause(incident.id, root.id, now=NOW + 11)
        return incident, root

    def test_integral_closed_twin_lifecycle(self):
        with ClosedDigitalTwin() as twin:
            twin.world.add_service("db", running=True, config={"mode": "good"})
            twin.world.add_service("api", running=True, config={"mode": "bad"}, dependencies=("db",))
            twin.world.fail_service("api", "configuration drift")
            (
                store, audit, obs, processor, incidents, identities, policy, engine,
                workspaces, checkpoints, planner, lab, validator
            ) = self._core(twin)
            try:
                engine.create_mission("m", "twin-system")
                engine.transition_mission("m", "AUTHORIZED", "digital twin authorization")
                engine.transition_mission("m", "RUNNING", "digital twin running")

                incident, _ = self._confirmed_root(twin, store, obs, processor, incidents)
                correction = planner.plan(
                    incident.id,
                    description="repair virtual api configuration",
                    task_kind="command",
                    argv=["twin-actuator", "repair-api"],
                    validation={"expected_files": {"proof/fixed.txt": "good"}, "audit_chain_required": True},
                    now=NOW + 12,
                )
                controller = identities.issue("twin-controller", "controller", ("remediation:authorize",), ttl_seconds=600, now=NOW)
                queued = lab.queue(correction.id, controller, now=NOW + 13)
                self.assertTrue(queued.checkpoint_id)
                lease = engine.claim_next("twin-worker", now=NOW + 14)
                self.assertIsNotNone(lease)
                self.assertEqual(queued.task_id, lease.id)

                actuator = TwinActuator(twin.world)
                actuator.apply("set_config", {"service": "api", "key": "mode", "value": "good"})
                actuator.apply("restart_service", {"service": "api"})
                workspace = workspaces.for_task("m", lease.id)
                proof = workspace / "proof" / "fixed.txt"
                proof.parent.mkdir(parents=True, exist_ok=True)
                proof.write_text("good", encoding="utf-8")
                engine.complete_task(lease, now=NOW + 15)

                result = validator.validate(correction.id, now=NOW + 16)
                self.assertTrue(result.passed)
                self.assertFalse(result.rolled_back)
                validator.finalize_incident(correction.id, result, recovery_verified=True, regression_verified=True, now=NOW + 17)
                self.assertEqual("RESOLVED", incidents.incident(incident.id).state)
                self.assertTrue(twin.world.services["api"].running)
                self.assertEqual("good", twin.world.services["api"].config["mode"])

                learning = ControlledLearningEngine(store, identities, obs, audit)
                registrar = identities.issue("registrar", "controller", ("knowledge:register",), ttl_seconds=600, now=NOW)
                reviewer = identities.issue("reviewer", "validator", ("knowledge:review",), ttl_seconds=600, now=NOW)
                promoter = identities.issue("promoter", "controller", ("knowledge:promote",), ttl_seconds=600, now=NOW)
                candidate = learning.create_candidate_from_correction(
                    registrar,
                    correction_id=correction.id,
                    lineage_key="virtual-api-config-repair",
                    kind="remediation",
                    content={"action": "set mode=good then restart", "virtual": True},
                    target_scope="SYSTEM",
                    now=NOW + 18,
                )
                self.assertEqual("QUARANTINED", candidate.state)
                learning.review_integrity(reviewer, candidate.id, now=NOW + 19)
                promoted = learning.promote(promoter, candidate.id, now=NOW + 20)
                self.assertEqual("PROMOTED", promoted.state)

                proposal = ProviderManager([], identities, audit).propose(
                    ProviderRequest(mission_id="m", objective="continue safely without AI"), timeout_seconds=0.1, now=NOW + 21
                )
                self.assertTrue(proposal.degraded)
                self.assertEqual("deterministic-no-ai", proposal.provider_id)

                OperationalStore(store, audit).bind_identity(identities)
                read = ReadModel(store, freshness_seconds=120)
                self.assertIn(read.dashboard(now=NOW + 22)["health"]["state"], {"HEALTHY", "DEGRADED"})

                backups = StateBackupManager(store, twin.path("backups"), audit)
                supervisor = ContinuousSupervisor(
                    store, engine, obs, audit, backups,
                    probes={"api": lambda: twin.world.services["api"].running, "db": lambda: twin.world.services["db"].running},
                    backup_interval_seconds=1,
                    restore_drill_interval_seconds=1,
                    backup_retention=3,
                )
                supervisor.boot(now=NOW + 23)
                cycle = supervisor.tick(now=NOW + 25)
                self.assertEqual("RUNNING", cycle.state)
                self.assertIsNotNone(cycle.backup_id)
                self.assertTrue(cycle.restore_drill_ok)
                self.assertEqual("HEALTHY", HeartbeatWatchdog(store, stale_after_seconds=30).check(now=NOW + 26).state)

                releases = ReleaseManager(twin.path("runtime", "releases"), backups, audit)
                v1 = twin.path("bundles", "v1")
                v1.mkdir(parents=True, exist_ok=True)
                (v1 / "app.txt").write_text("v1", encoding="utf-8")
                ReleaseManager.write_manifest(v1, "1.0.0")
                a1 = releases.activate(releases.stage(v1), lambda p: (p / "app.txt").read_text() == "v1", now=NOW + 27)
                self.assertTrue(a1.active)

                v2 = twin.path("bundles", "v2")
                v2.mkdir(parents=True, exist_ok=True)
                (v2 / "app.txt").write_text("broken", encoding="utf-8")
                ReleaseManager.write_manifest(v2, "2.0.0")
                a2 = releases.activate(releases.stage(v2), lambda p: False, now=NOW + 28)
                self.assertFalse(a2.active)
                self.assertTrue(a2.rolled_back)
                self.assertEqual("1.0.0", releases.current()["version"])

                valid, bad_seq = audit.verify_chain()
                self.assertTrue(valid)
                self.assertIsNone(bad_seq)
                self.assertTrue(twin.guard.clean)
            finally:
                store.close()

    def test_snapshot_rollback_is_virtual_only(self):
        with ClosedDigitalTwin() as twin:
            twin.world.add_service("api", running=True, config={"mode": "good"})
            snapshot = twin.snapshot_to("before.json")
            before = twin.world.digest()
            twin.world.fail_service("api")
            twin.world.set_config("api", "mode", "bad")
            self.assertNotEqual(before, twin.world.digest())
            twin.restore_snapshot(snapshot)
            self.assertEqual(before, twin.world.digest())
            self.assertTrue(twin.guard.clean)

    def test_32_virtual_systems_are_isolated(self):
        with ClosedDigitalTwin() as twin:
            store = SQLiteStateStore(twin.path("load", "state.sqlite3"))
            audit = AuditLedger(store)
            obs = ObservabilityStore(store, audit)
            processor = SignalProcessor(obs)
            try:
                for i in range(32):
                    twin.world.add_service(f"svc-{i:02d}", running=True)
                twin.world.fail_service("svc-17")
                sensors = [TwinSensor(twin.world, f"svc-{i:02d}") for i in range(32)]
                cycle = DiscoveryEngine(sensors, obs, processor, AnomalyDetector(obs), audit=audit).run_cycle(now=NOW)
                self.assertEqual(32, cycle.sensors_ok)
                down = store.conn.execute("SELECT COUNT(*) FROM obs_signals WHERE severity='error' AND subject='service:svc-17'").fetchone()[0]
                other_down = store.conn.execute("SELECT COUNT(*) FROM obs_signals WHERE severity='error' AND subject<>'service:svc-17'").fetchone()[0]
                self.assertEqual(1, down)
                self.assertEqual(0, other_down)
                self.assertTrue(twin.guard.clean)
            finally:
                store.close()

    def test_restart_recovers_expired_virtual_lease(self):
        with ClosedDigitalTwin() as twin:
            db = twin.path("resume", "state.sqlite3")
            store = SQLiteStateStore(db)
            audit = AuditLedger(store)
            engine = DurableLoopEngine(store, audit)
            engine.create_mission("m", "twin")
            engine.transition_mission("m", "AUTHORIZED", "test")
            engine.transition_mission("m", "RUNNING", "test")
            tid = engine.submit_task("m", "virtual", {"x": 1}, idempotency_key="resume-1", now=NOW)
            lease = engine.claim_next("worker-a", lease_seconds=1, now=NOW)
            self.assertEqual(tid, lease.id)
            store.close()

            store2 = SQLiteStateStore(db)
            audit2 = AuditLedger(store2)
            engine2 = DurableLoopEngine(store2, audit2)
            summary = engine2.resume(now=NOW + 5)
            self.assertEqual(1, summary["recovered_leases"])
            lease2 = engine2.claim_next("worker-b", now=NOW + 6)
            self.assertEqual(tid, lease2.id)
            engine2.complete_task(lease2, now=NOW + 7)
            self.assertEqual("COMPLETED", store2.get_task(tid)["state"])
            store2.close()
            self.assertTrue(twin.guard.clean)

    def test_adversarial_external_effect_attempts_are_blocked(self):
        with ClosedDigitalTwin() as twin:
            with self.assertRaises(SandboxViolation):
                socket.create_connection(("203.0.113.10", 443), timeout=0.01)
            with self.assertRaises(SandboxViolation):
                urllib.request.urlopen("https://example.invalid/", timeout=0.01)
            with self.assertRaises(SandboxViolation):
                twin.path("..", "escape.txt")
            with self.assertRaises(SandboxViolation):
                subprocess.run(["echo", "forbidden"], check=False)
            outside = twin.root.parent / "immune-twin-forbidden-write.txt"
            with self.assertRaises(SandboxViolation):
                outside.write_text("forbidden", encoding="utf-8")
            self.assertGreaterEqual(len(twin.guard.violations), 4)

    def test_no_external_effects_in_normal_virtual_operation(self):
        with ClosedDigitalTwin() as twin:
            twin.world.add_service("a", running=True)
            actuator = TwinActuator(twin.world)
            actuator.apply("restart_service", {"service": "a"})
            actuator.apply("set_ai", {"available": False})
            twin.snapshot_to("normal.json")
            self.assertTrue(twin.guard.clean)


if __name__ == "__main__":
    unittest.main()
