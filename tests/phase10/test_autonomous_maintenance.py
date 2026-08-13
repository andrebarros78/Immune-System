from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.audit import AuditLedger
from immune_core.autonomy import AutonomousMaintenanceController, InternalAgentRegistry, WorkerBinding
from immune_core.checkpoints import CheckpointManager, WorkspaceManager
from immune_core.cognition import CognitiveCoordinator, CognitiveCore
from immune_core.engine import DurableLoopEngine
from immune_core.execution import PrivilegedExecutor, SafeExecutor, WorkerManifest
from immune_core.identity import IdentityAuthority
from immune_core.memory import CognitiveMemory
from immune_core.policy import PolicyGuard
from immune_core.privilege import PrivilegeAuthority
from immune_core.providers import DeterministicNoAIProvider, ProviderManager, ProviderProposal, ProviderRequest
from immune_core.skills import SkillRegistry
from immune_core.storage import SQLiteStateStore
from immune_core.workers import WorkerRunner

NOW = 2_000_000_000


class StaticRepairProvider:
    provider_id = "test-cognitive-provider"
    locality = "local"
    cost_per_call = 0.0

    def propose(self, request: ProviderRequest, *, timeout_seconds: float) -> ProviderProposal:
        code = "from pathlib import Path; Path('autonomous-repair.txt').write_text('repaired')"
        return ProviderProposal(
            self.provider_id,
            "repair proposed",
            hypotheses=("synthetic fault",),
            recommended_tasks=(
                {
                    "kind": "command",
                    "payload": {"mode": "safe", "argv": [sys.executable, "-c", code]},
                    "skill_id": None,
                    "risk": {},
                },
            ),
            confidence=0.95,
        )


class AutonomousMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = SQLiteStateStore(root / "state.db")
        self.audit = AuditLedger(self.store)
        self.identity = IdentityAuthority(b"I" * 32)
        self.policy = PolicyGuard.from_repository(ROOT, self.identity, self.audit)
        self.engine = DurableLoopEngine(self.store, self.audit)
        self.memory = CognitiveMemory(self.store, self.identity, self.audit)
        self.skills = SkillRegistry(self.store, self.identity, self.audit)
        self.workspaces = WorkspaceManager(root / "workspaces")
        self.checkpoints = CheckpointManager(root / "checkpoints", self.workspaces, self.audit)
        self.privileges = PrivilegeAuthority(b"P" * 32, self.identity, self.store, self.audit)
        self.safe = SafeExecutor(self.store, self.audit, self.policy, self.workspaces, self.checkpoints)
        self.privileged = PrivilegedExecutor(self.store, self.audit, self.policy, self.workspaces, self.checkpoints)
        self.runner = WorkerRunner(self.engine, self.safe, self.privileged, self.workspaces, self.checkpoints, self.privileges)
        self.controller_token = self.identity.issue("autonomy-controller", "controller", ("cognition:authorize",), ttl_seconds=600, now=NOW)
        self.worker_token = self.identity.issue("maintenance-worker", "worker", ("execute:safe",), ttl_seconds=600, now=NOW)
        self.validator_token = self.identity.issue("independent-validator", "validator", ("memory:promote",), ttl_seconds=600, now=NOW)
        self.manifest = WorkerManifest("maintenance-worker", ("command",), ("write",), "task-scoped", (Path(sys.executable).name,))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def create_running(self, mission_id: str):
        self.engine.create_mission(mission_id, f"system-{mission_id}")
        self.engine.transition_mission(mission_id, "AUTHORIZED", "test")
        self.engine.transition_mission(mission_id, "RUNNING", "test")

    def controller(self, provider):
        core = CognitiveCore(ProviderManager([provider], self.identity, self.audit), self.memory, self.skills, self.audit)
        coordinator = CognitiveCoordinator(self.store, self.engine, self.policy, self.skills, self.audit)
        return AutonomousMaintenanceController(self.store, core, coordinator, self.runner, self.audit)

    def test_internal_cognitive_agents_are_immune_core_exclusive(self):
        registry = InternalAgentRegistry()
        cognitive = [a for a in registry.public_view() if a["uses_cognitive_provider"]]
        self.assertGreaterEqual(len(cognitive), 3)
        self.assertTrue(all(a["provider_scope"] == "immune-core" for a in cognitive))
        self.assertFalse(registry.get("diagnostician").can_execute)
        self.assertTrue(registry.get("executor").can_execute)
        self.assertFalse(registry.get("executor").uses_cognitive_provider)

    def test_autonomous_cycle_repairs_validates_and_promotes_learning(self):
        self.create_running("m1")
        controller = self.controller(StaticRepairProvider())

        def independent_validation(result):
            if not result.queued_task_ids:
                return False
            workspace = self.workspaces.for_task("m1", result.queued_task_ids[0])
            target = workspace / "autonomous-repair.txt"
            return target.exists() and target.read_text() == "repaired"

        result = controller.run_cycle(
            mission_id="m1",
            objective="restore synthetic service health",
            controller_token=self.controller_token,
            workers=(WorkerBinding(self.manifest, self.worker_token),),
            observations=({"service": "synthetic", "healthy": False},),
            memory_validator_token=self.validator_token,
            independent_validation=independent_validation,
            now=NOW,
        )
        self.assertEqual(result.state, "COMPLETED")
        self.assertEqual(len(result.queued_task_ids), 1)
        self.assertEqual(result.worker_outcomes[0].state, "COMPLETED")
        self.assertTrue(result.learning_promoted)
        self.assertEqual(self.memory.get(result.learning_memory_id).state, "PROMOTED")
        valid, bad = self.audit.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(bad)

    def test_worker_claim_is_scoped_to_requested_mission(self):
        self.create_running("m1")
        self.create_running("m2")
        payload = {"mode": "safe", "argv": [sys.executable, "-c", "pass"]}
        t1 = self.engine.submit_task("m1", "command", payload, idempotency_key="m1-task", now=NOW)
        t2 = self.engine.submit_task("m2", "command", payload, idempotency_key="m2-task", now=NOW)
        outcome = self.runner.run_once(self.manifest, self.worker_token, mission_id="m1", now=NOW)
        self.assertEqual(outcome.task_id, t1)
        self.assertEqual(self.store.get_task(t1)["state"], "COMPLETED")
        self.assertEqual(self.store.get_task(t2)["state"], "QUEUED")

    def test_no_ai_mode_stays_safe_and_does_not_queue_actions(self):
        self.create_running("m1")
        controller = self.controller(DeterministicNoAIProvider())
        result = controller.run_cycle(
            mission_id="m1",
            objective="keep service healthy",
            controller_token=self.controller_token,
            workers=(WorkerBinding(self.manifest, self.worker_token),),
            observations=({"probe": "ok"},),
            now=NOW,
        )
        self.assertEqual(result.state, "DEGRADED_NO_AI")
        self.assertEqual(result.queued_task_ids, ())
        self.assertEqual(result.worker_outcomes, ())
        self.assertIsNone(result.learning_memory_id)


if __name__ == "__main__":
    unittest.main()
