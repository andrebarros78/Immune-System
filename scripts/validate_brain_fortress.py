from __future__ import annotations

import ast
import json
import os
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_fortress.boundary import core_boundary_violations

EVIDENCE = ROOT / "evidence" / "brain-fortress-validation.json"
STATUS = ROOT / "BRAIN_FORTRESS_STATUS.md"


def main() -> int:
    started = time.time()
    checks: list[dict] = []
    failures: list[str] = []

    def ok(name: str, condition: object, detail: object = "") -> None:
        passed = bool(condition)
        checks.append({"name": name, "passed": passed, "detail": str(detail)})
        if not passed:
            failures.append(name)

    cfg = json.loads((ROOT / "config" / "brain-fortress.json").read_text(encoding="utf-8"))
    rings = cfg.get("rings", [])
    ok("seven_rings_exact", [r.get("ring") for r in rings] == list(range(1, 8)))
    ok("ring1_zero_network", rings[0].get("network") is False)
    ok("ring1_zero_subprocess", rings[0].get("subprocess") is False)
    ok("ring1_zero_adapters", rings[0].get("adapters") is False)
    ok("ring1_zero_external_credentials", rings[0].get("external_credentials") is False)
    ok("production_hardware_root_required", cfg.get("foundation", {}).get("production_hardware_backed_required") is True)
    ok("acceptance_state_exact", cfg.get("acceptance_state") == "BRAIN_FORTRESS_PROVEN")
    ring4 = rings[3]
    ring6 = rings[5]
    ok("worker_network_deny_default", ring4.get("worker_network_default") == "deny")
    ok("worker_child_process_deny_default", ring4.get("worker_child_process_default") == "deny")
    ok("worker_resource_limits_required", ring4.get("resource_limits_required") is True)
    ok("worker_disposable_teardown_required", ring4.get("disposable_teardown_required") is True)
    ok("adapter_signed_manifest_required", ring6.get("signed_manifest_required") is True)
    ok("adapter_process_isolation_required", ring6.get("process_isolation_required") is True)
    ok("adapter_network_deny_default", ring6.get("network_default") == "deny")
    ok("adapter_disposable_runtime_required", ring6.get("disposable_runtime_required") is True)

    violations = core_boundary_violations(ROOT)
    ok("core_static_boundary_clean", not violations, violations)
    core_execution = (ROOT / "immune_core" / "execution.py").read_text(encoding="utf-8")
    core_provider = (ROOT / "immune_core" / "providers.py").read_text(encoding="utf-8")
    core_provider_runtime = (ROOT / "immune_core" / "provider_runtime.py").read_text(encoding="utf-8")
    core_panel = (ROOT / "immune_core" / "panel.py").read_text(encoding="utf-8")
    ok("core_no_subprocess_implementation", "subprocess" not in core_execution)
    ok("core_no_http_provider", "urlopen" not in core_provider and "urllib" not in core_provider)
    ok("core_no_provider_secret_reference", "api_key_env" not in core_provider_runtime)
    ok("core_no_http_panel", "http.server" not in core_panel and "ThreadingHTTPServer" not in core_panel)
    ok("execution_broker_external", (ROOT / "immune_execution_broker" / "execution.py").is_file())
    ok("disposable_container_sandbox_present", (ROOT / "immune_execution_broker" / "isolation.py").is_file())
    ok("signed_adapter_manifest_present", (ROOT / "immune_fortress" / "adapter_manifest.py").is_file())
    ok("adapter_sandbox_host_present", (ROOT / "immune_gateway" / "adapter_sandbox.py").is_file())
    ok("provider_proxy_external", (ROOT / "immune_provider_proxy" / "http_provider.py").is_file())
    ok("presentation_external", (ROOT / "immune_presentation" / "panel.py").is_file())
    ok("control_plane_external", (ROOT / "immune_control_plane" / "cli.py").is_file())
    dynamic_core = "\n".join(path.read_text(encoding="utf-8-sig") for path in sorted((ROOT / "immune_core").glob("*.py")))
    for forbidden_dynamic in ("__import__(", "eval(", "exec(", "importlib."):
        ok(f"core_no_dynamic_code:{forbidden_dynamic}", forbidden_dynamic not in dynamic_core)

    cap_source = (ROOT / "immune_fortress" / "capability.py").read_text(encoding="utf-8")
    auth_source = (ROOT / "immune_fortress" / "policy_authority.py").read_text(encoding="utf-8")
    egress_source = (ROOT / "immune_gateway" / "egress.py").read_text(encoding="utf-8")
    contracts_source = (ROOT / "immune_gateway" / "contracts.py").read_text(encoding="utf-8")
    ingress_source = (ROOT / "immune_gateway" / "ingress.py").read_text(encoding="utf-8")
    ok("capability_one_use_store", "used_action_capabilities" in cap_source and "already consumed" in cap_source)
    ok("capability_exact_parameter_binding", "parameters_sha256" in cap_source and "parameter_digest" in cap_source)
    ok("capability_bounded_ttl", "MAX_TTL_SECONDS = 90" in cap_source)
    ok("policy_facts_derived", "mission_authorized =" in auth_source and "checkpoint_verifier" in auth_source)
    contracts_tree = ast.parse(contracts_source)
    egress_fields: set[str] = set()
    for node in contracts_tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "EgressRequest":
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    egress_fields.add(item.target.id)
    ok("egress_request_contract_found", bool(egress_fields), sorted(egress_fields))
    for forbidden in ("checkpoint_valid", "recovery_verified", "material_change", "irreversible"):
        ok(f"egress_request_has_no_caller_fact:{forbidden}", forbidden not in egress_fields, sorted(egress_fields))
    ok("gateway_consumes_exact_capability", "self.capabilities.consume" in egress_source)
    ok("gateway_uses_adapter_risk", "adapter.action_policy" in egress_source)
    ok("gateway_verifies_checkpoint", "adapter.verify_checkpoint" in egress_source)
    ok("gateway_ingress_nonce_replay_defense", "gateway_nonces" in ingress_source and "replayed gateway nonce" in ingress_source)

    ok("root_trust_present", (ROOT / "immune_fortress" / "root_trust.py").is_file())
    ok("fail_closed_boot_gate_present", (ROOT / "immune_fortress" / "bootstrap.py").is_file())
    root_critical = json.loads((ROOT / "config" / "brain-root-critical-files.json").read_text(encoding="utf-8"))
    critical_paths = root_critical.get("critical_files", [])
    ok("root_manifest_has_broad_critical_coverage", isinstance(critical_paths, list) and len(critical_paths) >= 30)
    ok("root_manifest_covers_policy", "immune_core/policy.py" in critical_paths)
    ok("root_manifest_covers_gateway", "immune_gateway/egress.py" in critical_paths)
    ok("root_manifest_covers_provider_proxy", "immune_provider_proxy/http_provider.py" in critical_paths)
    ok("root_manifest_covers_runtime", "scripts/immune_runtime.py" in critical_paths)
    ok("root_manifest_covers_fortress_config", "config/brain-fortress.json" in critical_paths)
    for required_root_file in (
        "immune_execution_broker/isolation.py",
        "immune_fortress/adapter_manifest.py",
        "immune_gateway/adapter_sandbox.py",
        "scripts/validate_container_sandbox.py",
        "config/provider-live-attestation.json",
        "scripts/verify_provider_live_attestation.py",
    ):
        ok(f"root_manifest_covers:{required_root_file}", required_root_file in critical_paths)
    ok("root_manifest_covers_all_rego", all(f"policies/{name}" in critical_paths for name in ("authority.rego","checkpoint.rego","destructive-actions.rego","donor-oss.rego","financial.rego","mission-proven.rego","secrets.rego")))
    runtime_source = (ROOT / "scripts" / "immune_runtime.py").read_text(encoding="utf-8")
    ok("official_runtime_has_fortress_attestation", "attest_fortress(args)" in runtime_source and "CONTAINED_EXIT" in runtime_source)
    ok("attestation_precedes_state_open", runtime_source.index("attest_fortress(args)") < runtime_source.index("SQLiteStateStore(db)"))
    ok("audit_external_seal_present", (ROOT / "immune_vault" / "audit_seal.py").is_file())
    ok("memory_promotion_seal_present", (ROOT / "immune_vault" / "memory_seal.py").is_file())
    sanitizer = (ROOT / "immune_provider_proxy" / "sanitizer.py").read_text(encoding="utf-8")
    ok("provider_dlp_secret_redaction", "[REDACTED]" in sanitizer and "SECRET_KEYS" in sanitizer)
    ok("provider_prompt_injection_detection", "INJECTION_MARKERS" in sanitizer and "QUARANTINED_UNTRUSTED_INSTRUCTION" in sanitizer)

    gateway_cfg = json.loads((ROOT / "config" / "gateway-runtime.json").read_text(encoding="utf-8"))
    ok("default_has_zero_protected_targets", gateway_cfg.get("systems") == [])
    provider_attestation = json.loads((ROOT / "config" / "provider-live-attestation.json").read_text(encoding="utf-8"))
    ok("provider_attestation_external_repository_exact", provider_attestation.get("repository") == "andrebarros78/Immune-System")
    ok("provider_attestation_requires_surface_identity", len(provider_attestation.get("surface_paths", [])) >= 6)
    ok("provider_attestation_has_external_run", int(provider_attestation.get("github_run_id", 0)) > 0)

    for phase in range(1, 11):
        text = (ROOT / f"PHASE{phase}_STATUS.md").read_text(encoding="utf-8")
        ok(f"phase_{phase}_still_proven", f"PHASE{phase}_PROVEN" in text)
    ok("base_mission_still_proven", "MISSION_PROVEN" in (ROOT / "MISSION_STATUS.md").read_text(encoding="utf-8"))
    ok("digital_twin_still_proven", "DIGITAL_TWIN_PROVEN" in (ROOT / "DIGITAL_TWIN_STATUS.md").read_text(encoding="utf-8"))

    compromise_source = (ROOT / "tests" / "fortress" / "test_compromise_containment.py").read_text(encoding="utf-8")
    ok("double_compromise_provider_gateway_required", "test_double_compromise_provider_plus_gateway_cannot_create_material_authority" in compromise_source)
    ok("double_compromise_adapter_worker_required", "test_double_compromise_adapter_plus_worker_cannot_expand_action_or_executable" in compromise_source)
    fortress_suite = unittest.defaultTestLoader.discover(str(ROOT / "tests" / "fortress"), pattern="test_*.py")

    def _test_ids(suite):
        ids = set()
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                ids.update(_test_ids(item))
            else:
                ids.add(item.id().rsplit(".", 1)[-1])
        return ids

    fortress_test_ids = _test_ids(fortress_suite)
    mandatory_attack_tests = {
        "test_double_compromise_provider_plus_gateway_cannot_create_material_authority",
        "test_double_compromise_adapter_plus_worker_cannot_expand_action_or_executable",
        "test_joint_constitution_policy_and_manifest_tamper_fails_external_root",
        "test_container_policy_is_deny_by_default_and_resource_bounded",
        "test_signed_adapter_manifest_detects_tamper_and_action_expansion",
        "test_official_runtime_fails_closed_when_root_key_is_unavailable",
        "test_stolen_tokens_expire_and_wrong_scope_cannot_authorize_or_replay",
        "test_attestation_reuse_requires_unchanged_surface_and_external_success",
        "test_provider_surface_change_forces_fresh_live_proof_without_reusing_attestation",
        "test_failed_or_mismatched_external_run_cannot_be_reused",
    }
    ok("mandatory_attack_scenarios_explicit", mandatory_attack_tests.issubset(fortress_test_ids), sorted(mandatory_attack_tests - fortress_test_ids))
    if os.environ.get("GITHUB_ACTIONS", "").strip().lower() == "true":
        ok("ci_disposable_sandbox_runtime_proven", os.environ.get("IMMUNE_DISPOSABLE_SANDBOX_PROVEN") == "true")
    fortress_result = unittest.TextTestRunner(verbosity=1).run(fortress_suite)
    ok("fortress_adversarial_suite", fortress_result.wasSuccessful(), f"tests={fortress_result.testsRun} failures={len(fortress_result.failures)} errors={len(fortress_result.errors)}")

    twin_suite = unittest.defaultTestLoader.discover(str(ROOT / "tests" / "digital_twin"), pattern="test_*.py")
    twin_result = unittest.TextTestRunner(verbosity=1).run(twin_suite)
    ok("closed_twin_security_suite", twin_result.wasSuccessful(), f"tests={twin_result.testsRun}")

    proven = not failures
    evidence = {
        "schema": 1,
        "scope": "SOVEREIGN_BRAIN_FORTRESS_V1_CLOSED_LAB",
        "status": "BRAIN_FORTRESS_PROVEN" if proven else "BRAIN_FORTRESS_NOT_PROVEN",
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "rings": 7,
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c["passed"]),
        "checks_failed": len(failures),
        "fortress_tests": fortress_result.testsRun,
        "digital_twin_tests": twin_result.testsRun,
        "protected_systems_attached": 0,
        "external_effects": 0,
        "production_hardware_root": "REQUIRED_AT_HOST_DEPLOYMENT",
        "closed_lab_root_backend": cfg.get("foundation", {}).get("closed_lab_backend"),
        "checks": checks,
        "duration_seconds": time.time() - started,
    }
    EVIDENCE.parent.mkdir(exist_ok=True)
    EVIDENCE.write_text(json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    STATUS.write_text(
        "# Sovereign Brain Fortress\n\n"
        + f"**Estado: {evidence['status']}**\n\n"
        + "Escopo: `SOVEREIGN_BRAIN_FORTRESS_V1_CLOSED_LAB`.\n\n"
        + f"Anéis: 7/7. Checks: {evidence['checks_passed']}/{evidence['checks_total']}. "
        + f"Testes fortress: {fortress_result.testsRun}. Digital Twin: {twin_result.testsRun}.\n\n"
        + "O Core não possui rede, subprocesso, adapters, painel HTTP ou credencial de provider. "
        + "Ações materiais exigem capability criptográfica one-shot e checkpoint verificado pela fronteira.\n\n"
        + "A raiz de confiança de laboratório é externa e efêmera; implantação física exige backend hardware-backed/TPM e sua própria evidência de host.\n",
        encoding="utf-8",
    )
    print(json.dumps({k: evidence[k] for k in ("status", "checks_total", "checks_passed", "checks_failed", "fortress_tests", "digital_twin_tests", "protected_systems_attached", "external_effects")}, sort_keys=True))
    return 0 if proven else 1


if __name__ == "__main__":
    raise SystemExit(main())
