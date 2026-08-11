from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from immune_core.audit import AuditLedger
from immune_core.checkpoints import CheckpointError, CheckpointManager, WorkspaceManager
from immune_core.engine import DurableLoopEngine
from immune_core.execution import AuthorizationError, PrivilegedExecutor, SafeExecutor, WorkerManifest
from immune_core.identity import IdentityAuthority
from immune_core.policy import PolicyGuard
from immune_core.privilege import PrivilegeAuthority, PrivilegeError
from immune_core.storage import SQLiteStateStore
from immune_core.workers import WorkerRunner

ROOT = Path(__file__).resolve().parents[2]
PYEXE = str(Path(sys.executable).resolve())
PYNAME = Path(PYEXE).name


class Phase3ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = SQLiteStateStore(root / "state.db")
        self.audit = AuditLedger(self.store)
        self.identities = IdentityAuthority(b"I" * 32)
        self.policy = PolicyGuard.from_repository(ROOT, self.identities, self.audit)
        self.workspaces = WorkspaceManager(root / "workspaces")
        self.checkpoints = CheckpointManager(root / "checkpoints", self.workspaces, self.audit)
        self.privileges = PrivilegeAuthority(b"P" * 32, self.identities, self.store, self.audit)
        self.engine = DurableLoopEngine(self.store, self.audit)
        self.safe = SafeExecutor(self.store, self.audit, self.policy, self.workspaces, self.checkpoints)
        self.priv = PrivilegedExecutor(self.store, self.audit, self.policy, self.workspaces, self.checkpoints)
        self.runner = WorkerRunner(self.engine, self.safe, self.priv, self.workspaces, self.checkpoints, self.privileges)
        self.safe_manifest = WorkerManifest("worker-safe", ("command",), ("write",), "task-scoped", (PYNAME,), max_runtime_seconds=2, max_output_bytes=2048, env_allowlist=("VISIBLE",))
        self.priv_manifest = WorkerManifest("worker-priv", ("command",), ("host-change",), "privileged-ephemeral", (PYNAME,), max_runtime_seconds=2, max_output_bytes=2048)
        now = int(time.time())
        self.safe_token = self.identities.issue("worker-safe", "worker", ("execute:safe",), ttl_seconds=3600, now=now)
        self.priv_token = self.identities.issue("worker-priv", "worker", ("execute:privileged",), ttl_seconds=3600, now=now)
        self.authorizer_token = self.identities.issue("sovereign-controller", "controller", ("grant:privileged",), ttl_seconds=3600, now=now)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def mission(self, mission_id="m1", system_id="s1", state="RUNNING"):
        self.engine.create_mission(mission_id, system_id)
        if state == "RUNNING":
            self.engine.transition_mission(mission_id, "AUTHORIZED", "test")
            self.engine.transition_mission(mission_id, "RUNNING", "test")
        else:
            self.store.set_mission_state(mission_id, state, "test")
        return mission_id

    def lease(self, manifest, payload=None, mission_id="m1"):
        if self.store.get_mission(mission_id) is None:
            self.mission(mission_id)
        task_id = self.engine.submit_task(mission_id, "command", payload or {"argv": [PYEXE, "-c", "print('ok')"]}, idempotency_key=f"k-{time.time_ns()}")
        lease = self.engine.claim_next(manifest.id)
        self.assertIsNotNone(lease)
        return task_id, lease

    def test_manifest_rejects_invalid_authority(self):
        with self.assertRaises(ValueError):
            WorkerManifest("x", ("command",), ("x",), "root", (PYNAME,))

    def test_workspace_is_derived_and_confined(self):
        a = self.workspaces.for_task("m", "t1")
        b = self.workspaces.for_task("m", "t2")
        self.assertNotEqual(a, b)
        self.assertTrue(self.workspaces.contains(a))
        self.assertTrue(self.workspaces.contains(b))

    def test_checkpoint_restore_roundtrip(self):
        ws = self.workspaces.for_task("m", "t")
        (ws / "state.txt").write_text("before", encoding="utf-8")
        cp = self.checkpoints.create(ws, "m", "t")
        (ws / "state.txt").write_text("after", encoding="utf-8")
        self.assertTrue(self.checkpoints.verify(cp))
        self.checkpoints.restore(cp, ws)
        self.assertEqual((ws / "state.txt").read_text(encoding="utf-8"), "before")

    def test_tampered_checkpoint_is_rejected(self):
        ws = self.workspaces.for_task("m", "t")
        (ws / "x.txt").write_text("x", encoding="utf-8")
        cp = self.checkpoints.create(ws, "m", "t")
        (Path(cp.path) / "data" / "x.txt").write_text("tamper", encoding="utf-8")
        self.assertFalse(self.checkpoints.verify(cp))
        with self.assertRaises(CheckpointError):
            self.checkpoints.restore(cp, ws)

    def test_safe_execution_success(self):
        _, lease = self.lease(self.safe_manifest)
        result = self.safe.run(lease, self.safe_manifest, self.safe_token, [PYEXE, "-c", "from pathlib import Path; Path('made.txt').write_text('ok')"])
        self.assertEqual(result.returncode, 0)
        ws = self.workspaces.for_task(lease.mission_id, lease.id)
        self.assertEqual((ws / "made.txt").read_text(), "ok")

    def test_disallowed_executable_is_blocked(self):
        _, lease = self.lease(self.safe_manifest)
        with self.assertRaises(AuthorizationError):
            self.safe.run(lease, self.safe_manifest, self.safe_token, ["not-allowed", "x"])

    def test_missing_worker_scope_is_blocked(self):
        _, lease = self.lease(self.safe_manifest)
        token = self.identities.issue("worker-safe", "worker", ("observe",), ttl_seconds=60)
        with self.assertRaises(AuthorizationError):
            self.safe.run(lease, self.safe_manifest, token, [PYEXE, "-c", "print(1)"])

    def test_lease_owner_mismatch_is_blocked(self):
        _, lease = self.lease(self.safe_manifest)
        wrong = WorkerManifest("other-worker", ("command",), ("write",), "task-scoped", (PYNAME,))
        with self.assertRaises(AuthorizationError):
            self.safe.run(lease, wrong, self.safe_token, [PYEXE, "-c", "print(1)"])

    def test_kind_outside_manifest_is_blocked(self):
        _, lease = self.lease(self.safe_manifest)
        wrong = WorkerManifest("worker-safe", ("other",), ("write",), "task-scoped", (PYNAME,))
        with self.assertRaises(AuthorizationError):
            self.safe.run(lease, wrong, self.safe_token, [PYEXE, "-c", "print(1)"])

    def test_inactive_mission_is_blocked_before_policy(self):
        self.mission("blocked", state="BLOCKED")
        _, lease = self.lease(self.safe_manifest, mission_id="blocked")
        with self.assertRaises(AuthorizationError):
            self.safe.run(lease, self.safe_manifest, self.safe_token, [PYEXE, "-c", "print(1)"])

    def test_non_allowlisted_environment_is_blocked(self):
        _, lease = self.lease(self.safe_manifest)
        with self.assertRaises(AuthorizationError):
            self.safe.run(lease, self.safe_manifest, self.safe_token, [PYEXE, "-c", "print(1)"], env={"SECRET_TOKEN": "no"})

    def test_environment_is_minimal_and_explicit(self):
        _, lease = self.lease(self.safe_manifest)
        os.environ["IMMUNE_TEST_SECRET"] = "must-not-leak"
        try:
            result = self.safe.run(lease, self.safe_manifest, self.safe_token, [PYEXE, "-c", "import os; print(os.getenv('VISIBLE')); print(os.getenv('IMMUNE_TEST_SECRET'))"], env={"VISIBLE": "yes"})
        finally:
            os.environ.pop("IMMUNE_TEST_SECRET", None)
        self.assertIn("yes", result.stdout)
        self.assertIn("None", result.stdout)

    def test_timeout_is_enforced(self):
        _, lease = self.lease(self.safe_manifest)
        result = self.safe.run(lease, self.safe_manifest, self.safe_token, [PYEXE, "-c", "import time; time.sleep(1)"], timeout_seconds=0.05)
        self.assertEqual(result.returncode, 124)

    def test_failed_material_change_rolls_back(self):
        _, lease = self.lease(self.safe_manifest)
        ws = self.workspaces.for_task(lease.mission_id, lease.id)
        (ws / "state.txt").write_text("before", encoding="utf-8")
        result = self.safe.run(lease, self.safe_manifest, self.safe_token, [PYEXE, "-c", "from pathlib import Path; Path('state.txt').write_text('bad'); raise SystemExit(7)"], material_change=True)
        self.assertEqual(result.returncode, 7)
        self.assertTrue(result.rolled_back)
        self.assertEqual((ws / "state.txt").read_text(), "before")

    def test_output_is_bounded(self):
        manifest = WorkerManifest("worker-safe", ("command",), ("write",), "task-scoped", (PYNAME,), max_output_bytes=1024)
        _, lease = self.lease(manifest)
        result = self.safe.run(lease, manifest, self.safe_token, [PYEXE, "-c", "print('x'*5000)"])
        self.assertLess(len(result.stdout.encode()), 1200)
        self.assertIn("truncated", result.stdout)

    def test_privilege_issue_requires_authorizer_scope(self):
        bad = self.identities.issue("x", "controller", ("observe",), ttl_seconds=60)
        with self.assertRaises(PrivilegeError):
            self.privileges.issue(bad, mission_id="m", task_id="t", worker_id="w", action="a", checkpoint_id="c")

    def test_privilege_ttl_is_bounded(self):
        with self.assertRaises(PrivilegeError):
            self.privileges.issue(self.authorizer_token, mission_id="m", task_id="t", worker_id="w", action="a", checkpoint_id="c", ttl_seconds=301)

    def test_privilege_target_mismatch_is_blocked(self):
        grant = self.privileges.issue(self.authorizer_token, mission_id="m", task_id="t", worker_id="w", action="a", checkpoint_id="c")
        with self.assertRaises(PrivilegeError):
            self.privileges.consume(grant.token, mission_id="m", task_id="other", worker_id="w", action="a", checkpoint_id="c")

    def test_privilege_grant_is_one_use(self):
        grant = self.privileges.issue(self.authorizer_token, mission_id="m", task_id="t", worker_id="w", action="a", checkpoint_id="c")
        kwargs = dict(mission_id="m", task_id="t", worker_id="w", action="a", checkpoint_id="c")
        self.privileges.consume(grant.token, **kwargs)
        with self.assertRaises(PrivilegeError):
            self.privileges.consume(grant.token, **kwargs)

    def test_privileged_worker_manifest_is_required(self):
        _, lease = self.lease(self.safe_manifest)
        ws = self.workspaces.for_task(lease.mission_id, lease.id)
        cp = self.checkpoints.create(ws, lease.mission_id, lease.id)
        grant = self.privileges.issue(self.authorizer_token, mission_id=lease.mission_id, task_id=lease.id, worker_id=self.safe_manifest.id, action="write", checkpoint_id=cp.id)
        with self.assertRaises(AuthorizationError):
            self.priv.run_privileged(lease, self.safe_manifest, self.safe_token, [PYEXE, "-c", "print(1)"], privilege_authority=self.privileges, grant_token=grant.token, action="write", checkpoint=cp)

    def test_privileged_action_must_be_manifest_capability(self):
        _, lease = self.lease(self.priv_manifest)
        ws = self.workspaces.for_task(lease.mission_id, lease.id)
        cp = self.checkpoints.create(ws, lease.mission_id, lease.id)
        grant = self.privileges.issue(self.authorizer_token, mission_id=lease.mission_id, task_id=lease.id, worker_id=self.priv_manifest.id, action="other", checkpoint_id=cp.id)
        with self.assertRaises(AuthorizationError):
            self.priv.run_privileged(lease, self.priv_manifest, self.priv_token, [PYEXE, "-c", "print(1)"], privilege_authority=self.privileges, grant_token=grant.token, action="other", checkpoint=cp)

    def test_privileged_execution_success(self):
        _, lease = self.lease(self.priv_manifest)
        ws = self.workspaces.for_task(lease.mission_id, lease.id)
        cp = self.checkpoints.create(ws, lease.mission_id, lease.id)
        grant = self.privileges.issue(self.authorizer_token, mission_id=lease.mission_id, task_id=lease.id, worker_id=self.priv_manifest.id, action="host-change", checkpoint_id=cp.id)
        result = self.priv.run_privileged(lease, self.priv_manifest, self.priv_token, [PYEXE, "-c", "from pathlib import Path; Path('priv.txt').write_text('ok')"], privilege_authority=self.privileges, grant_token=grant.token, action="host-change", checkpoint=cp)
        self.assertEqual(result.returncode, 0)
        self.assertTrue((ws / "priv.txt").exists())

    def test_runner_safe_completes_durable_task(self):
        self.mission()
        task_id = self.engine.submit_task("m1", "command", {"mode": "safe", "argv": [PYEXE, "-c", "print('ok')"]}, idempotency_key="runner-safe")
        out = self.runner.run_once(self.safe_manifest, self.safe_token)
        self.assertEqual(out.state, "COMPLETED")
        self.assertEqual(out.task_id, task_id)
        self.assertEqual(self.store.get_task(task_id)["state"], "COMPLETED")

    def test_runner_blocks_inactive_mission(self):
        self.mission("blocked", state="BLOCKED")
        task_id = self.engine.submit_task("blocked", "command", {"mode": "safe", "argv": [PYEXE, "-c", "print('no')"]}, idempotency_key="runner-blocked")
        out = self.runner.run_once(self.safe_manifest, self.safe_token)
        self.assertEqual(out.state, "BLOCKED")
        self.assertEqual(self.store.get_task(task_id)["state"], "BLOCKED")

    def test_runner_privileged_requires_external_authorizer(self):
        self.mission()
        task_id = self.engine.submit_task("m1", "command", {"mode": "privileged", "action": "host-change", "argv": [PYEXE, "-c", "print('x')"]}, idempotency_key="runner-no-auth")
        out = self.runner.run_once(self.priv_manifest, self.priv_token)
        self.assertEqual(out.state, "BLOCKED")
        self.assertEqual(self.store.get_task(task_id)["state"], "BLOCKED")

    def test_runner_privileged_end_to_end(self):
        self.mission()
        task_id = self.engine.submit_task("m1", "command", {"mode": "privileged", "action": "host-change", "argv": [PYEXE, "-c", "from pathlib import Path; Path('p.txt').write_text('done')"]}, idempotency_key="runner-priv")
        out = self.runner.run_once(self.priv_manifest, self.priv_token, privilege_authorizer_token=self.authorizer_token)
        self.assertEqual(out.state, "COMPLETED")
        self.assertEqual(self.store.get_task(task_id)["state"], "COMPLETED")

    def test_runner_failure_requeues_when_attempts_remain(self):
        self.mission()
        task_id = self.engine.submit_task("m1", "command", {"mode": "safe", "argv": [PYEXE, "-c", "raise SystemExit(9)"]}, idempotency_key="runner-retry", max_attempts=2)
        out = self.runner.run_once(self.safe_manifest, self.safe_token)
        self.assertEqual(out.state, "QUEUED")
        self.assertEqual(self.store.get_task(task_id)["state"], "QUEUED")

    def test_audit_chain_remains_valid_after_execution(self):
        self.mission()
        self.engine.submit_task("m1", "command", {"mode": "safe", "argv": [PYEXE, "-c", "print('audit')"]}, idempotency_key="audit")
        self.runner.run_once(self.safe_manifest, self.safe_token)
        valid, bad_seq = self.audit.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(bad_seq)


if __name__ == "__main__":
    unittest.main()
