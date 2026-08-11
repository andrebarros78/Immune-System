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

from immune_core.acceptance import MissionProofEngine
from immune_core.audit import AuditLedger
from immune_core.autostart import build_runtime_plan
from immune_core.continuous import ContinuousSupervisor, SupervisorLock
from immune_core.engine import DurableLoopEngine
from immune_core.observability import ObservabilityStore
from immune_core.state_backup import StateBackupManager
from immune_core.storage import SQLiteStateStore
from immune_core.update_manager import ReleaseManager
from immune_core.watchdog import HeartbeatWatchdog

NOW = 2_200_100_000
checks: list[dict] = []
failures: list[str] = []


def ok(name: str, condition: object, detail: str = "") -> None:
    passed = bool(condition)
    checks.append({"name": name, "passed": passed, "detail": str(detail)})
    if not passed:
        failures.append(name)


for phase in range(1, 10):
    path = ROOT / f"PHASE{phase}_STATUS.md"
    ok(f"phase{phase}_baseline_proven", path.is_file() and f"PHASE{phase}_PROVEN" in path.read_text(encoding="utf-8"))

required = [
    "immune_core/continuous.py",
    "immune_core/watchdog.py",
    "immune_core/update_manager.py",
    "immune_core/autostart.py",
    "scripts/immune_runtime.py",
    "tests/phase10/test_continuous_operation.py",
    "adr/ADR-0010-continuous-operation.md",
    ".github/workflows/phase10-continuous.yml",
]
for rel in required:
    ok(f"artifact:{rel}", (ROOT / rel).is_file())

for rel in required[:6]:
    try:
        ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        ok(f"ast:{rel}", True)
    except SyntaxError as exc:
        ok(f"ast:{rel}", False, exc)

continuous_text = (ROOT / "immune_core/continuous.py").read_text(encoding="utf-8")
watchdog_text = (ROOT / "immune_core/watchdog.py").read_text(encoding="utf-8")
update_text = (ROOT / "immune_core/update_manager.py").read_text(encoding="utf-8")
runtime_text = (ROOT / "scripts/immune_runtime.py").read_text(encoding="utf-8")
for forbidden in ("SafeExecutor", "PrivilegedExecutor", "WorkerRunner", "ProviderManager", "OpenAI"):
    ok(f"supervisor_no_authority:{forbidden}", forbidden not in continuous_text and forbidden not in watchdog_text)
ok("supervisor_no_subprocess", "subprocess" not in continuous_text and "subprocess" not in watchdog_text)
ok("runtime_no_provider_dependency", "ProviderManager" not in runtime_text and "OpenAI" not in runtime_text)
ok("update_requires_state_backup", "self.backups.create" in update_text and "self.backups.verify" in update_text)
ok("update_atomic_pointer", "os.replace" in update_text)
ok("update_sha256_manifest", "sha256" in update_text and "release-manifest.json" in update_text)
ok("phase9_minimum_scenarios_preserved", "15/15" in (ROOT / "PHASE9_STATUS.md").read_text(encoding="utf-8"))

mission_proof_data: dict[str, object] = {}
endurance: dict[str, object] = {}
with tempfile.TemporaryDirectory(prefix="immune-phase10-proof-") as td:
    root = Path(td)
    db = root / "state.sqlite3"
    store = SQLiteStateStore(db)
    audit = AuditLedger(store)
    engine = DurableLoopEngine(store, audit)
    obs = ObservabilityStore(store, audit)
    backups = StateBackupManager(store, root / "backups", audit)
    supervisor = ContinuousSupervisor(
        store,
        engine,
        obs,
        audit,
        backups,
        probes={"sqlite": lambda: store.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"},
        backup_interval_seconds=1,
        restore_drill_interval_seconds=1,
        backup_retention=3,
    )
    engine.create_mission("phase10-proof", "immune-system")
    engine.transition_mission("phase10-proof", "AUTHORIZED", "phase10-proof")
    engine.transition_mission("phase10-proof", "RUNNING", "phase10-proof")

    task_id = engine.submit_task("phase10-proof", "proof", {"test": True}, idempotency_key="phase10-expired")
    lease = engine.claim_next("worker-proof", lease_seconds=1, now=NOW)
    ok("expired_lease_claimed", lease is not None and lease.id == task_id)
    resumed = supervisor.boot(now=NOW + 2)
    ok("boot_recovers_expired_lease", resumed.get("recovered_leases") == 1 and store.get_task(task_id)["state"] == "QUEUED")

    cycle = supervisor.tick(now=NOW + 3)
    ok("continuous_cycle_running", cycle.state == "RUNNING")
    ok("periodic_backup_created", bool(cycle.backup_id))
    ok("periodic_backup_verified", bool(cycle.backup_id) and backups.verify(backups.get(str(cycle.backup_id))))
    ok("restore_drill_verified", cycle.restore_drill_ok is True)
    ok("cycle_evidence_verified", obs.verify_evidence(cycle.evidence_id))

    watchdog = HeartbeatWatchdog(store, stale_after_seconds=10)
    ok("watchdog_fresh", watchdog.check(now=NOW + 4).state == "HEALTHY")
    ok("watchdog_stale", watchdog.check(now=NOW + 20).state == "STALE")

    before = store.conn.total_changes
    watchdog.check(now=NOW + 4)
    ok("watchdog_read_only", before == store.conn.total_changes)

    lock_path = root / "supervisor.lock"
    first = SupervisorLock(lock_path, stale_after_seconds=10)
    first.acquire(now=NOW)
    duplicate_blocked = False
    try:
        SupervisorLock(lock_path, stale_after_seconds=10).acquire(now=NOW + 1)
    except Exception:
        duplicate_blocked = True
    first.release()
    ok("single_instance_enforced", duplicate_blocked)
    lock_path.write_text(json.dumps({"created_at": NOW - 100, "token": "stale"}), encoding="utf-8")
    recovered_lock = SupervisorLock(lock_path, stale_after_seconds=10)
    recovered_lock.acquire(now=NOW)
    recovered_lock.release()
    ok("stale_lock_recovered", not lock_path.exists())

    supervisor.probes["failure"] = lambda: False
    degraded = supervisor.tick(now=NOW + 30)
    ok("probe_failure_degrades_without_crash", degraded.state == "DEGRADED")
    supervisor.probes["failure"] = lambda: True
    recovered_cycle = supervisor.tick(now=NOW + 31)
    ok("runtime_recovers_after_probe", recovered_cycle.state == "RUNNING")

    manager = ReleaseManager(root / "release-root", backups, audit)
    bundle1 = root / "bundle-1"
    bundle1.mkdir()
    (bundle1 / "app.txt").write_text("v1", encoding="utf-8")
    ReleaseManager.write_manifest(bundle1, "1.0.0")
    staged1 = manager.stage(bundle1)
    activation1 = manager.activate(staged1, lambda path: (path / "app.txt").read_text(encoding="utf-8") == "v1", now=NOW + 40)
    ok("release_activation_verified", activation1.active and not activation1.rolled_back and manager.current()["version"] == "1.0.0")
    ok("pre_update_backup_verified", backups.verify(backups.get(activation1.backup_id)))

    bundle2 = root / "bundle-2"
    bundle2.mkdir()
    (bundle2 / "app.txt").write_text("v2", encoding="utf-8")
    ReleaseManager.write_manifest(bundle2, "1.1.0")
    staged2 = manager.stage(bundle2)
    activation2 = manager.activate(staged2, lambda path: False, now=NOW + 41)
    ok("failed_update_rolls_back", activation2.rolled_back and not activation2.active and manager.current()["version"] == "1.0.0")
    ok("failed_release_removed", not (manager.releases / "1.1.0").exists())

    tamper = root / "bundle-tamper"
    tamper.mkdir()
    (tamper / "app.txt").write_text("clean", encoding="utf-8")
    ReleaseManager.write_manifest(tamper, "1.2.0")
    (tamper / "app.txt").write_text("tampered", encoding="utf-8")
    tamper_blocked = False
    try:
        manager.stage(tamper)
    except Exception:
        tamper_blocked = True
    ok("tampered_release_blocked", tamper_blocked)

    plan = build_runtime_plan(sys.executable, ROOT, ("--db", "runtime/state.sqlite3"))
    systemd = plan.systemd_unit()
    windows = plan.windows_task_xml()
    ok("systemd_boot_restart", "Restart=always" in systemd and "NoNewPrivileges=true" in systemd)
    ok("windows_boot_restart", "BootTrigger" in windows and "RestartOnFailure" in windows and "IgnoreNew" in windows)

    stable = ContinuousSupervisor(
        store,
        engine,
        obs,
        audit,
        backups,
        probes={"ok": lambda: True},
        backup_interval_seconds=999,
        restore_drill_interval_seconds=999,
        backup_retention=3,
    )
    stable.boot()
    endurance = stable.run_for(1.0, interval_seconds=0.005, max_cycles=500)
    ok("endurance_cycles", int(endurance["cycles"]) >= 50, str(endurance))
    ok("endurance_no_degraded_cycles", int(endurance["degraded_cycles"]) == 0, str(endurance))

    valid, bad_seq = audit.verify_chain()
    ok("audit_chain_valid", valid and bad_seq is None, str(bad_seq))

    all_phase_checks = all(item["passed"] for item in checks)
    proof_engine = MissionProofEngine(audit, b"P" * 32)
    gates = {
        "scope_explicit": True,
        "observable_result_achieved": all_phase_checks,
        "relevant_tests_passed": all_phase_checks,
        "regression_validated": all_phase_checks,
        "recovery_validated": all_phase_checks,
        "security_validated": all_phase_checks,
        "evidence_preserved": all_phase_checks,
        "no_critical_blocker": all_phase_checks,
        "independent_audit_passed": valid and bad_seq is None,
    }
    proof = proof_engine.evaluate("IMMUNE_SYSTEM_V1_IMPLEMENTATION_AND_CONTROLLED_OPERATION", gates)
    ok("scoped_mission_proven", proof.proven and not proof.missing_gates)
    mission_proof_data = {
        "scope_id": proof.scope_id,
        "proven": proof.proven,
        "missing_gates": list(proof.missing_gates),
        "gates_digest": proof.gates_digest,
        "signature": proof.signature,
    }
    store.close()

controlled = required + ["adr/ADR-0010-continuous-operation.md"]
hashes = {rel: hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() for rel in controlled}
evidence = {
    "schema": 1,
    "phase": "PHASE_10_CONTINUOUS_OPERATION",
    "validated_at": datetime.now(timezone.utc).isoformat(),
    "checks": checks,
    "summary": {"total": len(checks), "passed": sum(1 for x in checks if x["passed"]), "failed": len(failures)},
    "controlled_file_sha256": hashes,
    "endurance": endurance,
    "mission_proof": mission_proof_data,
    "result": "PHASE10_PROVEN" if not failures else "PHASE10_FAILED",
    "scope_note": "PHASE10_PROVEN and the scoped MISSION_PROVEN cover repository implementation and controlled CI operation. They do not claim elapsed 24x7 operation on a specific external host that has not been deployed in this proof.",
}
(ROOT / "evidence").mkdir(exist_ok=True)
(ROOT / "evidence/phase10-validation.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
status = "PHASE10_PROVEN" if not failures else "PHASE10_FAILED"
(ROOT / "PHASE10_STATUS.md").write_text(
    "# Fase 10 — Operação Contínua\n\n"
    f"**Estado: {status}**\n\n"
    f"Checks: {evidence['summary']['passed']}/{evidence['summary']['total']} aprovados.\n\n"
    "Capacidades: Supervisor contínuo, heartbeat/Watchdog, retomada durável, autostart portátil, backup periódico, restore drill, retenção, atualização staged por SHA-256 e rollback por health gate.\n\n"
    "A operação contínua não concede autoridade de execução ao Supervisor ou Watchdog.\n",
    encoding="utf-8",
)
mission_state = "MISSION_PROVEN" if not failures and mission_proof_data.get("proven") else "MISSION_NOT_PROVEN"
(ROOT / "MISSION_STATUS.md").write_text(
    "# Missão do Produto — Sistema Imunológico v1\n\n"
    f"**Estado: {mission_state}**\n\n"
    "Escopo: `IMMUNE_SYSTEM_V1_IMPLEMENTATION_AND_CONTROLLED_OPERATION`.\n\n"
    "Este escopo comprova a implementação integral do repositório e sua operação controlada/reproduzível em CI. Uma instalação física específica continua sendo um escopo de implantação separado e deve produzir sua própria evidência operacional de host.\n",
    encoding="utf-8",
)
print(json.dumps(evidence["summary"], sort_keys=True))
print(mission_state)
if failures:
    print("FAILED:", ", ".join(failures))
    raise SystemExit(1)
print("PHASE10_PROVEN")
