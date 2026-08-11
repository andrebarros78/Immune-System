from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from immune_core.audit import AuditLedger
from immune_core.autostart import build_runtime_plan
from immune_core.continuous import ContinuousOperationError, ContinuousSupervisor, SupervisorLock
from immune_core.engine import DurableLoopEngine
from immune_core.observability import ObservabilityStore
from immune_core.state_backup import StateBackupManager
from immune_core.storage import SQLiteStateStore
from immune_core.update_manager import ReleaseManager, UpdateError
from immune_core.watchdog import HeartbeatWatchdog


ROOT = Path(__file__).resolve().parents[2]
NOW = 2_200_000_000


class Phase10Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "state.sqlite3"
        self.store = SQLiteStateStore(self.db)
        self.audit = AuditLedger(self.store)
        self.engine = DurableLoopEngine(self.store, self.audit)
        self.obs = ObservabilityStore(self.store, self.audit)
        self.backups = StateBackupManager(self.store, self.root / "backups", self.audit)
        self.supervisor = ContinuousSupervisor(
            self.store,
            self.engine,
            self.obs,
            self.audit,
            self.backups,
            probes={"sqlite": lambda: self.store.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"},
            backup_interval_seconds=10,
            restore_drill_interval_seconds=20,
            backup_retention=3,
        )
        self.engine.create_mission("m", "system")
        self.engine.transition_mission("m", "AUTHORIZED", "phase10")
        self.engine.transition_mission("m", "RUNNING", "phase10")

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def _release(self, version: str, content: str) -> Path:
        root = self.root / f"bundle-{version}"
        root.mkdir()
        (root / "app.txt").write_text(content, encoding="utf-8")
        ReleaseManager.write_manifest(root, version)
        return root

    def test_boot_recovers_expired_lease(self):
        task_id = self.engine.submit_task("m", "proof", {"x": 1}, idempotency_key="lease")
        lease = self.engine.claim_next("worker-a", lease_seconds=1, now=NOW)
        self.assertEqual(task_id, lease.id)
        summary = self.supervisor.boot(now=NOW + 2)
        self.assertEqual(summary["recovered_leases"], 1)
        self.assertEqual(self.store.get_task(task_id)["state"], "QUEUED")

    def test_healthy_tick_creates_verified_backup_and_restore_drill(self):
        self.supervisor.boot(now=NOW)
        cycle = self.supervisor.tick(now=NOW + 1)
        self.assertEqual(cycle.state, "RUNNING")
        self.assertIsNotNone(cycle.backup_id)
        self.assertTrue(cycle.restore_drill_ok)
        ref = self.backups.get(cycle.backup_id)
        self.assertTrue(self.backups.verify(ref))
        self.assertTrue(self.obs.verify_evidence(cycle.evidence_id))

    def test_probe_failure_is_contained_as_degraded(self):
        self.supervisor.probes["broken"] = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        self.supervisor.boot(now=NOW)
        first = self.supervisor.tick(now=NOW + 1)
        self.assertEqual(first.state, "DEGRADED")
        self.supervisor.probes["broken"] = lambda: True
        second = self.supervisor.tick(now=NOW + 2)
        self.assertEqual(second.state, "RUNNING")

    def test_backup_retention_is_bounded(self):
        supervisor = ContinuousSupervisor(
            self.store, self.engine, self.obs, self.audit, self.backups,
            probes={"ok": lambda: True}, backup_interval_seconds=1,
            restore_drill_interval_seconds=1000, backup_retention=2,
        )
        supervisor.boot(now=NOW)
        for offset in (1, 2, 3, 4):
            supervisor.tick(now=NOW + offset)
        self.assertLessEqual(len(list(self.backups.root.glob("*.json"))), 2)
        self.assertLessEqual(len(list(self.backups.root.glob("*.sqlite3"))), 2)

    def test_supervisor_lock_blocks_duplicate_and_recovers_stale(self):
        path = self.root / "supervisor.lock"
        first = SupervisorLock(path, stale_after_seconds=10)
        first.acquire(now=NOW)
        with self.assertRaises(ContinuousOperationError):
            SupervisorLock(path, stale_after_seconds=10).acquire(now=NOW + 1)
        first.release()
        path.write_text(json.dumps({"created_at": NOW - 100, "token": "old"}), encoding="utf-8")
        replacement = SupervisorLock(path, stale_after_seconds=10)
        replacement.acquire(now=NOW)
        replacement.release()
        self.assertFalse(path.exists())

    def test_watchdog_detects_fresh_stale_and_stopped(self):
        self.supervisor.boot(now=NOW)
        watchdog = HeartbeatWatchdog(self.store, stale_after_seconds=10)
        self.assertEqual(watchdog.check(now=NOW + 1).state, "HEALTHY")
        self.assertEqual(watchdog.check(now=NOW + 20).state, "STALE")
        self.supervisor.stop(now=NOW + 21)
        self.assertEqual(watchdog.check(now=NOW + 22).state, "STOPPED")

    def test_watchdog_is_read_only(self):
        self.supervisor.boot(now=NOW)
        watchdog = HeartbeatWatchdog(self.store, stale_after_seconds=10)
        before = self.store.conn.total_changes
        watchdog.check(now=NOW + 1)
        self.assertEqual(before, self.store.conn.total_changes)

    def test_runtime_state_survives_restart(self):
        self.supervisor.boot(now=NOW)
        self.supervisor.tick(now=NOW + 1)
        boot_count = self.supervisor.status()["boot_count"]
        self.store.close()
        self.store = SQLiteStateStore(self.db)
        self.audit = AuditLedger(self.store)
        self.engine = DurableLoopEngine(self.store, self.audit)
        self.obs = ObservabilityStore(self.store, self.audit)
        self.backups = StateBackupManager(self.store, self.root / "backups", self.audit)
        resumed = ContinuousSupervisor(self.store, self.engine, self.obs, self.audit, self.backups)
        self.assertEqual(resumed.status()["boot_count"], boot_count)
        resumed.boot(now=NOW + 100)
        self.assertEqual(resumed.status()["boot_count"], boot_count + 1)

    def test_release_activation_is_verified_and_backed_up(self):
        manager = ReleaseManager(self.root / "releases-root", self.backups, self.audit)
        staged = manager.stage(self._release("1.0.0", "v1"))
        result = manager.activate(staged, lambda path: (path / "app.txt").read_text(encoding="utf-8") == "v1", now=NOW)
        self.assertTrue(result.active)
        self.assertFalse(result.rolled_back)
        self.assertEqual(manager.current()["version"], "1.0.0")
        self.assertTrue(self.backups.verify(self.backups.get(result.backup_id)))

    def test_tampered_release_is_rejected_before_activation(self):
        manager = ReleaseManager(self.root / "releases-root", self.backups, self.audit)
        bundle = self._release("1.0.0", "v1")
        (bundle / "app.txt").write_text("tampered", encoding="utf-8")
        with self.assertRaises(UpdateError):
            manager.stage(bundle)
        self.assertIsNone(manager.current())

    def test_failed_health_gate_rolls_back_release_pointer(self):
        manager = ReleaseManager(self.root / "releases-root", self.backups, self.audit)
        v1 = manager.stage(self._release("1.0.0", "v1"))
        manager.activate(v1, lambda path: True, now=NOW)
        v2 = manager.stage(self._release("1.1.0", "v2"))
        result = manager.activate(v2, lambda path: False, now=NOW + 1)
        self.assertFalse(result.active)
        self.assertTrue(result.rolled_back)
        self.assertEqual(manager.current()["version"], "1.0.0")
        self.assertFalse((manager.releases / "1.1.0").exists())

    def test_release_version_cannot_move_backward(self):
        manager = ReleaseManager(self.root / "releases-root", self.backups, self.audit)
        v2 = manager.stage(self._release("2.0.0", "v2"))
        manager.activate(v2, lambda path: True, now=NOW)
        with self.assertRaises(UpdateError):
            manager.stage(self._release("1.9.9", "old"))

    def test_autostart_specs_boot_and_restart_without_privilege_bypass(self):
        plan = build_runtime_plan(sys.executable, ROOT, ("--db", "runtime/state.sqlite3"))
        systemd = plan.systemd_unit()
        windows = plan.windows_task_xml()
        self.assertIn("Restart=always", systemd)
        self.assertIn("NoNewPrivileges=true", systemd)
        self.assertIn("BootTrigger", windows)
        self.assertIn("RestartOnFailure", windows)
        self.assertIn("IgnoreNew", windows)

    def test_continuous_endurance_window_has_no_failures(self):
        supervisor = ContinuousSupervisor(
            self.store, self.engine, self.obs, self.audit, self.backups,
            probes={"ok": lambda: True}, backup_interval_seconds=999,
            restore_drill_interval_seconds=999, backup_retention=3,
        )
        supervisor.boot()
        result = supervisor.run_for(0.6, interval_seconds=0.01, max_cycles=200)
        self.assertGreaterEqual(result["cycles"], 20)
        self.assertEqual(result["degraded_cycles"], 0)
        self.assertEqual(result["state"], "RUNNING")

    def test_continuous_core_has_no_ai_or_executor_authority(self):
        continuous = (ROOT / "immune_core/continuous.py").read_text(encoding="utf-8")
        watchdog = (ROOT / "immune_core/watchdog.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "SafeExecutor", "PrivilegedExecutor", "WorkerRunner", "ProviderManager", "OpenAI"):
            self.assertNotIn(forbidden, continuous)
            self.assertNotIn(forbidden, watchdog)

    def test_audit_chain_remains_valid(self):
        self.supervisor.boot(now=NOW)
        self.supervisor.tick(now=NOW + 1)
        manager = ReleaseManager(self.root / "releases-root", self.backups, self.audit)
        staged = manager.stage(self._release("1.0.0", "v1"))
        manager.activate(staged, lambda path: True, now=NOW + 2)
        valid, bad_seq = self.audit.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(bad_seq)


if __name__ == "__main__":
    unittest.main()
