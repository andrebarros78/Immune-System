#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_json(relative: str) -> dict:
    path = ROOT / relative
    if not path.is_file():
        raise SystemExit(f"MISSING_EVIDENCE:{relative}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"INVALID_EVIDENCE_OBJECT:{relative}")
    return data


def require(condition: object, label: str) -> None:
    if not condition:
        raise SystemExit(f"FINAL_GATE_FAILED:{label}")


def main() -> int:
    phase_summary: dict[str, dict] = {}
    for phase in range(1, 11):
        rel = f"evidence/phase{phase}-validation.json"
        data = load_json(rel)
        expected = f"PHASE{phase}_PROVEN"
        require(data.get("result") == expected, f"phase{phase}_result")
        summary = data.get("summary") or {}
        require(int(summary.get("failed", 1)) == 0, f"phase{phase}_failed_zero")
        checks = data.get("checks") or []
        require(bool(checks) and all(item.get("passed") is True for item in checks), f"phase{phase}_all_checks")
        phase_summary[str(phase)] = {
            "result": data.get("result"),
            "passed": int(summary.get("passed", 0)),
            "total": int(summary.get("total", 0)),
        }

    phase9 = load_json("evidence/phase9-validation.json")
    load = (phase9.get("metrics") or {}).get("load") or {}
    endurance9 = (phase9.get("metrics") or {}).get("endurance") or {}
    require(load.get("levels") == [1, 4, 8, 16, 32], "phase9_load_levels")
    require(int(load.get("tasks", 0)) == 61, "phase9_load_tasks")
    require(int(endurance9.get("cycles", 0)) >= 128, "phase9_endurance_cycles")
    require(int(endurance9.get("failures", 1)) == 0, "phase9_endurance_zero_failures")

    phase10 = load_json("evidence/phase10-validation.json")
    proof = phase10.get("mission_proof") or {}
    require(proof.get("proven") is True, "phase10_scoped_mission_proven")
    require(not proof.get("missing_gates"), "phase10_no_missing_gates")
    endurance10 = phase10.get("endurance") or {}
    require(int(endurance10.get("cycles", 0)) >= 50, "phase10_endurance_cycles")
    require(int(endurance10.get("degraded_cycles", 1)) == 0, "phase10_zero_degraded_cycles")

    twin = load_json("evidence/digital-twin-validation.json")
    require(twin.get("status") == "DIGITAL_TWIN_PROVEN", "digital_twin_proven")
    require(int(twin.get("checks_failed", 1)) == 0, "digital_twin_zero_failures")
    require(int(twin.get("external_effects_performed", 1)) == 0, "digital_twin_zero_external_effects")
    require(twin.get("external_effect_policy") == "SEM_EFEITO_EXTERNO", "digital_twin_external_policy")
    twin_checks = {str(item.get("name")): bool(item.get("passed")) for item in (twin.get("checks") or [])}
    for required_gateway_gate in (
        "gateway_adapter_artifact",
        "gateway_adapter_no_network_or_subprocess_imports",
        "gateway_adapter_bounded_actions",
        "scenario_gateway_egress",
        "scenario_gateway_checkpoint_gate",
        "scenario_gateway_twin_adapter",
        "scenario_gateway_rollback",
    ):
        require(twin_checks.get(required_gateway_gate) is True, f"digital_twin:{required_gateway_gate}")

    gateway = load_json("config/gateway-runtime.json")
    require(gateway.get("owner_scope") == "immune-gateway", "gateway_owner")
    require(gateway.get("systems") == [], "gateway_default_has_no_protected_systems")

    provider = load_json("config/provider-live-test.json")
    profiles = provider.get("providers") or []
    require(provider.get("owner_scope") == "immune-core", "provider_owner")
    require(len(profiles) == 1, "isolated_provider_count")
    endpoint = str(profiles[0].get("endpoint", ""))
    require(endpoint.startswith("https://api.z.ai/"), "isolated_provider_endpoint")
    encoded = json.dumps(provider).lower()
    for forbidden in ("127.0.0.1", "localhost", "windows-mcp", "wmcp", "tunel-core", "tunnel-core"):
        require(forbidden not in encoded, f"isolated_provider_forbidden:{forbidden}")

    mission_status = (ROOT / "MISSION_STATUS.md").read_text(encoding="utf-8")
    require("MISSION_PROVEN" in mission_status, "mission_status_proven")

    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        sha = "unknown"

    result = {
        "MISSION_PROVEN": True,
        "scope": "IMMUNE_SYSTEM_V1_ISOLATED_INTEGRAL_PROOF",
        "commit": sha,
        "phases": phase_summary,
        "phase9_endurance_cycles": int(endurance9.get("cycles", 0)),
        "phase10_endurance_cycles": int(endurance10.get("cycles", 0)),
        "digital_twin_checks": int(twin.get("checks_passed", 0)),
        "external_effects": 0,
        "protected_systems_attached": 0,
        "live_provider_gate": "SEPARATE_REQUIRED_JOB",
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
