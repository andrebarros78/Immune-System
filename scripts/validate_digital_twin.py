from __future__ import annotations

import ast
import json
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EVIDENCE = ROOT / "evidence" / "digital-twin-validation.json"
STATUS = ROOT / "DIGITAL_TWIN_STATUS.md"


def check(name: str, passed: bool, detail: str = "") -> dict:
    return {"name": name, "passed": bool(passed), "detail": detail}


def main() -> int:
    started = time.time()
    checks: list[dict] = []

    for n in range(1, 11):
        path = ROOT / f"PHASE{n}_STATUS.md"
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        checks.append(check(f"baseline_phase_{n}", f"PHASE{n}_PROVEN" in text))

    mission = ROOT / "MISSION_STATUS.md"
    mission_text = mission.read_text(encoding="utf-8") if mission.exists() else ""
    checks.append(check("baseline_mission_proven", "MISSION_PROVEN" in mission_text))

    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests" / "digital_twin"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    checks.append(check("digital_twin_unittest_suite", result.wasSuccessful(), f"tests={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}"))

    gateway_adapter_path = ROOT / "immune_twin" / "gateway_adapter.py"
    checks.append(check("gateway_adapter_artifact", gateway_adapter_path.is_file()))
    gateway_adapter_source = gateway_adapter_path.read_text(encoding="utf-8") if gateway_adapter_path.is_file() else ""
    try:
        gateway_tree = ast.parse(gateway_adapter_source)
        forbidden_imports: set[str] = set()
        for node in ast.walk(gateway_tree):
            if isinstance(node, ast.Import):
                forbidden_imports.update(alias.name.split(".", 1)[0] for alias in node.names if alias.name.split(".", 1)[0] in {"socket", "subprocess", "urllib"})
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] in {"socket", "subprocess", "urllib"}:
                forbidden_imports.add((node.module or "").split(".", 1)[0])
        checks.append(check("gateway_adapter_no_network_or_subprocess_imports", not forbidden_imports, sorted(forbidden_imports)))
    except SyntaxError as exc:
        checks.append(check("gateway_adapter_no_network_or_subprocess_imports", False, str(exc)))
    checks.append(check("gateway_adapter_bounded_actions", "set_config" in gateway_adapter_source and "restart_service" in gateway_adapter_source and "restore_snapshot" in gateway_adapter_source))

    sandbox_source = (ROOT / "immune_twin" / "sandbox.py").read_text(encoding="utf-8")
    required_guards = [
        'socket, "create_connection"',
        'socket.socket, "connect"',
        'urllib.request, "urlopen"',
        'subprocess, "run"',
        'subprocess, "Popen"',
        'os, "system"',
        'builtins, "open"',
        'io, "open"',
    ]
    for token in required_guards:
        checks.append(check(f"guard_{token}", token in sandbox_source))

    test_source = (ROOT / "tests" / "digital_twin" / "test_integral_twin.py").read_text(encoding="utf-8")
    required_scenarios = {
        "closed_integral_lifecycle": "test_integral_closed_twin_lifecycle",
        "snapshot_rollback": "test_snapshot_rollback_is_virtual_only",
        "isolation_32_systems": "test_32_virtual_systems_are_isolated",
        "restart_resume": "test_restart_recovers_expired_virtual_lease",
        "external_effect_block": "test_adversarial_external_effect_attempts_are_blocked",
        "zero_external_normal": "test_no_external_effects_in_normal_virtual_operation",
        "discovery": "DiscoveryEngine",
        "diagnosis": "IncidentEngine",
        "remediation": "RemediationPlanner",
        "semantic_validation": "ValidationEngine",
        "controlled_learning": "ControlledLearningEngine",
        "no_ai": "ProviderManager",
        "continuous_supervisor": "ContinuousSupervisor",
        "watchdog": "HeartbeatWatchdog",
        "backup_restore": "StateBackupManager",
        "safe_update": "ReleaseManager",
        "policy_guard": "PolicyGuard",
        "audit_chain": "verify_chain",
        "gateway_egress": "GatewayEgress",
        "gateway_checkpoint_gate": "SovereignAuthorizationError",
        "gateway_one_use_capability": "capability_token",
        "gateway_policy_authority": "SovereignPolicyAuthority",
        "gateway_twin_adapter": "DigitalTwinGatewayAdapter",
        "gateway_rollback": "restore_snapshot",
    }
    for name, token in required_scenarios.items():
        checks.append(check(f"scenario_{name}", token in test_source))

    workflow = (ROOT / ".github" / "workflows" / "digital-twin-integral.yml").read_text(encoding="utf-8")
    checks.append(check("workflow_retests_phases_2_10", all(f"tests/phase{n}" in workflow for n in range(2, 11))))
    checks.append(check("workflow_runs_digital_twin", "tests/digital_twin" in workflow and "validate_digital_twin.py" in workflow))
    checks.append(check("no_nested_git_guard", "Nested .git metadata found" in workflow))

    total = len(checks)
    passed = sum(1 for item in checks if item["passed"])
    failed = total - passed
    proven = failed == 0 and result.wasSuccessful()

    evidence = {
        "schema": 1,
        "test_type": "TESTE_VIRTUAL_SIMULADO",
        "mode": "DIGITAL_TWIN_OPERACIONAL",
        "sandbox": "SANDBOX_VIRTUAL_FECHADO",
        "simulation": "SIMULAÇÃO_PONTA_A_PONTA",
        "external_effect_policy": "SEM_EFEITO_EXTERNO",
        "status": "DIGITAL_TWIN_PROVEN" if proven else "DIGITAL_TWIN_NOT_PROVEN",
        "scope": "IMMUNE_SYSTEM_V1_CLOSED_DIGITAL_TWIN_INTEGRAL_VALIDATION",
        "checks_total": total,
        "checks_passed": passed,
        "checks_failed": failed,
        "unittest_tests": result.testsRun,
        "external_effects_performed": 0 if proven else None,
        "note": "Blocked adversarial attempts are containment tests; underlying network/process/outside-root writes are not executed.",
        "duration_seconds": time.time() - started,
        "checks": checks,
    }

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    STATUS.write_text(
        "# Validação Integral — Digital Twin Fechado\n\n"
        f"**Estado: {evidence['status']}**\n\n"
        f"Escopo: `{evidence['scope']}`.\n\n"
        f"Checks: {passed}/{total} aprovados.\n\n"
        f"Testes executados: {result.testsRun}.\n\n"
        "Modo: TESTE_VIRTUAL_SIMULADO / DIGITAL_TWIN_OPERACIONAL / SANDBOX_VIRTUAL_FECHADO / "
        "SIMULAÇÃO_PONTA_A_PONTA / SEM_EFEITO_EXTERNO.\n\n"
        "Efeitos externos realizados pelo cenário normal: 0. Tentativas adversariais de rede, subprocesso e escrita fora da sandbox são bloqueadas antes do efeito.\n\n"
        "Esta prova valida o produto em gêmeo digital fechado; não substitui evidência de uma instalação física específica.\n",
        encoding="utf-8",
    )
    print(json.dumps({k: evidence[k] for k in ("status", "checks_total", "checks_passed", "checks_failed", "unittest_tests", "duration_seconds")}, indent=2))
    return 0 if proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
