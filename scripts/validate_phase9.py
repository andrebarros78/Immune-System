#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

checks: list[dict[str, object]] = []
failures: list[str] = []


def check(name: str, condition: object, detail: object = "") -> None:
    passed = bool(condition)
    checks.append({"name": name, "passed": passed, "detail": str(detail)})
    if not passed:
        failures.append(name)


for phase in range(1, 9):
    path = ROOT / f"PHASE{phase}_STATUS.md"
    check(f"phase{phase}_baseline_proven", path.is_file() and f"PHASE{phase}_PROVEN" in path.read_text(encoding="utf-8"))

required = [
    "immune_core/operator_dispatch.py",
    "immune_core/state_backup.py",
    "tests/phase9/test_end_to_end_proof.py",
    "scripts/validate_phase9.py",
    "adr/ADR-0009-end-to-end-proof.md",
    ".github/workflows/phase9-end-to-end.yml",
]
for rel in required:
    check(f"artifact:{rel}", (ROOT / rel).is_file())

for rel in ("immune_core/operator_dispatch.py", "immune_core/state_backup.py", "tests/phase9/test_end_to_end_proof.py"):
    try:
        ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        check(f"ast:{rel}", True)
    except SyntaxError as exc:
        check(f"ast:{rel}", False, exc)

dispatch_text = (ROOT / "immune_core/operator_dispatch.py").read_text(encoding="utf-8")
backup_text = (ROOT / "immune_core/state_backup.py").read_text(encoding="utf-8")
test_text = (ROOT / "tests/phase9/test_end_to_end_proof.py").read_text(encoding="utf-8")
check("dispatcher_does_not_execute_host", "subprocess" not in dispatch_text and "os.system" not in dispatch_text and "shell=True" not in dispatch_text)
check("dispatcher_argv_is_registry_owned", "RunbookActionRegistry" in dispatch_text and "controlled.argv" in dispatch_text)
check("backup_uses_sqlite_consistent_backup", ".backup(destination)" in backup_text)
check("backup_checks_integrity", "PRAGMA integrity_check" in backup_text)
check("backup_verifies_sha256", "sha256" in backup_text and "_hash_file" in backup_text)
check("load_levels_declared", "levels = [1, 4, 8, 16, 32]" in test_text)
check("endurance_gate_declared", "duration, 2.0" in test_text and "cycles, 128" in test_text)

test_path = ROOT / "tests/phase9/test_end_to_end_proof.py"
spec = importlib.util.spec_from_file_location("phase9_proof_tests_for_validator", test_path)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)
suite = unittest.defaultTestLoader.loadTestsFromModule(module)
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)
check("phase9_suite_passed_in_validator", result.wasSuccessful(), stream.getvalue()[-4000:])
check("phase9_test_count_at_least_17", result.testsRun >= 17, result.testsRun)

method_names = sorted(name for name in dir(module.Phase9ProofTests) if name.startswith("test_"))
for n in range(1, 16):
    prefix = f"test_{n:02d}_"
    check(f"minimum_scenario_{n:02d}", any(name.startswith(prefix) for name in method_names))
check("security_scenario_present", any(name.startswith("test_16_") for name in method_names))
check("endurance_scenario_present", any(name.startswith("test_17_") for name in method_names))

metrics = dict(getattr(module, "PHASE9_METRICS", {}))
load = dict(metrics.get("load") or {})
endurance = dict(metrics.get("endurance") or {})
check("load_metrics_present", bool(load))
check("load_levels_proven", load.get("levels") == [1, 4, 8, 16, 32], load)
check("load_task_count_proven", int(load.get("tasks", 0)) == 61, load)
check("load_p50_recorded", float(load.get("p50_seconds", -1)) >= 0, load)
check("load_p95_recorded", float(load.get("p95_seconds", -1)) >= 0, load)
check("load_p99_under_ci_gate", 0 <= float(load.get("p99_seconds", -1)) < 10.0, load)
check("endurance_duration_proven", float(endurance.get("duration_seconds", 0)) >= 2.0, endurance)
check("endurance_cycles_proven", int(endurance.get("cycles", 0)) >= 128, endurance)
check("endurance_zero_failures", int(endurance.get("failures", 1)) == 0, endurance)

controlled = required
hashes = {rel: hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() for rel in controlled if (ROOT / rel).is_file()}
evidence = {
    "schema": 1,
    "phase": "PHASE_9_END_TO_END_PROOF",
    "validated_at": datetime.now(timezone.utc).isoformat(),
    "environment": {
        "runner_contract": "GitHub Actions ubuntu-24.04",
        "controlled_failure_scope": "temporary files, SQLite databases and loopback processes only",
        "external_effects": False,
    },
    "minimum_scenarios": 15,
    "executed_tests": result.testsRun,
    "metrics": metrics,
    "checks": checks,
    "summary": {"total": len(checks), "passed": sum(1 for item in checks if item["passed"]), "failed": len(failures)},
    "controlled_file_sha256": hashes,
    "result": "PHASE9_PROVEN" if not failures else "PHASE9_FAILED",
    "scope_note": "PHASE9_PROVEN proves the specification's controlled end-to-end scenarios on a real GitHub-hosted Linux runner, including real loopback process failure/recovery, regression, rollback, restart/resume, no-AI mode, backup/restore, 1/4/8/16/32 queue concurrency, bounded CI endurance and security gates. It does not claim 24x7 installed operation, multi-OS production deployment, or complete-product MISSION_PROVEN; Phase 10 remains required.",
}
(ROOT / "evidence").mkdir(exist_ok=True)
(ROOT / "evidence/phase9-validation.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
status = evidence["result"]
(ROOT / "PHASE9_STATUS.md").write_text(
    "# Fase 9 — Prova Ponta a Ponta\n\n"
    f"**Estado: {status}**\n\n"
    f"Checks: {evidence['summary']['passed']}/{evidence['summary']['total']} aprovados.\n\n"
    f"Cenários executados: {result.testsRun}; mínimos da especificação: 15/15 cobertos.\n\n"
    f"Carga: níveis {load.get('levels', [])}, tarefas={load.get('tasks', 0)}, p50={load.get('p50_seconds', 0):.6f}s, p95={load.get('p95_seconds', 0):.6f}s, p99={load.get('p99_seconds', 0):.6f}s.\n\n"
    f"Endurance CI: {endurance.get('duration_seconds', 0):.3f}s, {endurance.get('cycles', 0)} ciclos, falhas={endurance.get('failures', 0)}.\n\n"
    "Escopo: prova real controlada em runner Linux do GitHub; a Fase 10 ainda é necessária para Supervisor, instalação contínua, atualização segura, backup periódico e operação 24x7. O produto completo permanece sem MISSION_PROVEN.\n",
    encoding="utf-8",
)
print(json.dumps(evidence["summary"], sort_keys=True))
print(json.dumps(metrics, sort_keys=True))
if failures:
    print("FAILED:", ", ".join(failures))
    raise SystemExit(1)
print("PHASE9_PROVEN")
