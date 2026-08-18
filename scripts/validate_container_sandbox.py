from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_execution_broker.isolation import ContainerIsolationPolicy, ContainerSandboxRunner, SandboxIsolationError
from immune_fortress.adapter_manifest import AdapterManifest, AdapterManifestAuthority
from immune_gateway.adapter_sandbox import DisposableAdapterSandbox


REQUIRED = {
    "network_blocked": True,
    "child_process_blocked": True,
    "root_read_only": True,
    "secret_absent": True,
    "tmp_write_ok": True,
}


def assert_probe(label: str, result: dict) -> None:
    for key, expected in REQUIRED.items():
        if result.get(key) is not expected:
            raise RuntimeError(f"{label} containment failed: {key}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args = parser.parse_args(argv)

    policy = ContainerIsolationPolicy()
    runner = ContainerSandboxRunner(policy)

    try:
        policy.create_args(
            image_ref=args.image,
            env={"IMMUNE_PROVIDER_PRIMARY_API_KEY": "must-never-enter-sandbox"},
        )
    except SandboxIsolationError:
        secret_injection_blocked = True
    else:
        secret_injection_blocked = False
    if not secret_injection_blocked:
        raise RuntimeError("sandbox accepted secret-like environment injection")

    worker = runner.run_json_probe(image_ref=args.image, timeout=20)
    assert_probe("worker", worker)

    manifest_authority = AdapterManifestAuthority(b"A" * 32)
    manifest = AdapterManifest(
        adapter_id="closed-lab-hostile-adapter",
        version="1.0.0-lab",
        image_sha256=runner.image_sha256(args.image),
        capabilities=("probe",),
    )
    signed = manifest_authority.sign(manifest)
    adapter = DisposableAdapterSandbox(signed, manifest_authority, runner)
    adapter_result = adapter.run_json_probe(action="probe", image_ref=args.image, timeout=20)
    assert_probe("adapter", adapter_result)

    output = {
        "status": "DISPOSABLE_SANDBOX_PROVEN",
        "worker": worker,
        "adapter": adapter_result,
        "secret_injection_blocked": secret_injection_blocked,
        "network_mode": policy.network_mode,
        "pids_limit": policy.pids_limit,
        "memory_bytes": policy.memory_bytes,
        "cpus": policy.cpus,
        "read_only_root": policy.read_only_root,
        "cap_drop": list(policy.cap_drop),
        "no_new_privileges": policy.no_new_privileges,
    }
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
