from __future__ import annotations

import dataclasses
import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from immune_execution_broker.isolation import ContainerIsolationPolicy, SandboxIsolationError
from immune_fortress.adapter_manifest import AdapterManifest, AdapterManifestAuthority, AdapterManifestError
from immune_fortress.root_trust import BrainRootOfTrust, ExternalHMACRootKey, RootManifest, RootTrustError
from immune_gateway.adapter_sandbox import AdapterSandboxError, DisposableAdapterSandbox
from scripts.immune_runtime import CONTAINED_EXIT, main as immune_runtime_main


class _NeverRun:
    def run_json_probe(self, **kwargs):
        raise AssertionError("sandbox runner must not be reached for unauthorized adapter action")


class _DigestMismatchRunner:
    def image_sha256(self, image_ref, *, timeout=20.0):
        return "b" * 64
    def run_json_probe(self, **kwargs):
        raise AssertionError("mismatched image must never execute")


class FortressSandboxContractTests(unittest.TestCase):
    def test_container_policy_is_deny_by_default_and_resource_bounded(self):
        policy = ContainerIsolationPolicy()
        args = policy.create_args(image_ref="local-probe:sha", container_name="probe")
        joined = " ".join(args)
        self.assertIn("--network none", joined)
        self.assertIn("--pids-limit 1", joined)
        self.assertIn("--memory 134217728", joined)
        self.assertIn("--cpus 0.5", joined)
        self.assertIn("--read-only", args)
        self.assertIn("no-new-privileges:true", args)
        self.assertIn("--cap-drop ALL", joined)
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=16m", args)

    def test_container_policy_rejects_network_relaxation_and_secret_environment(self):
        with self.assertRaises(SandboxIsolationError):
            ContainerIsolationPolicy(network_mode="bridge")
        policy = ContainerIsolationPolicy(env_allowlist=("SAFE_FLAG", "IMMUNE_PROVIDER_PRIMARY_API_KEY"))
        with self.assertRaises(SandboxIsolationError):
            policy.create_args(image_ref="local-probe:sha", env={"IMMUNE_PROVIDER_PRIMARY_API_KEY": "x"})
        args = policy.create_args(image_ref="local-probe:sha", env={"SAFE_FLAG": "1"})
        self.assertIn("SAFE_FLAG=1", args)

    def test_signed_adapter_manifest_detects_tamper_and_action_expansion(self):
        authority = AdapterManifestAuthority(b"A" * 32)
        manifest = AdapterManifest(
            adapter_id="adapter-lab",
            version="1.0.0",
            image_sha256="a" * 64,
            capabilities=("probe",),
        )
        signed = authority.sign(manifest)
        authority.verify(signed)
        tampered = dataclasses.replace(
            signed,
            manifest=dataclasses.replace(manifest, capabilities=("probe", "wipe")),
        )
        with self.assertRaises(AdapterManifestError):
            authority.verify(tampered)
        sandbox = DisposableAdapterSandbox(signed, authority, _NeverRun())
        with self.assertRaises(AdapterSandboxError):
            sandbox.run_json_probe(action="wipe", image_ref="local-probe:sha")
        mismatch = DisposableAdapterSandbox(signed, authority, _DigestMismatchRunner())
        with self.assertRaises(AdapterSandboxError):
            mismatch.run_json_probe(action="probe", image_ref="attacker-image:latest")

    def test_joint_constitution_policy_and_manifest_tamper_fails_external_root(self):
        with tempfile.TemporaryDirectory(prefix="immune-joint-root-") as td:
            root = Path(td)
            (root / "constitution.md").write_text("sovereign=true\n", encoding="utf-8")
            (root / "policy.py").write_text("ALLOW=False\n", encoding="utf-8")
            trust = BrainRootOfTrust(root, ExternalHMACRootKey(b"R" * 32))
            manifest, signature = trust.build(("constitution.md", "policy.py"), generation=9, source_commit="trusted")
            trust.verify(manifest, signature, minimum_generation=9)

            (root / "constitution.md").write_text("attacker=true\n", encoding="utf-8")
            (root / "policy.py").write_text("ALLOW=True\n", encoding="utf-8")
            with self.assertRaises(RootTrustError):
                trust.verify(manifest, signature, minimum_generation=9)

            forged_files = {
                "constitution.md": hashlib.sha256((root / "constitution.md").read_bytes()).hexdigest(),
                "policy.py": hashlib.sha256((root / "policy.py").read_bytes()).hexdigest(),
            }
            forged_manifest = RootManifest(9, "trusted", forged_files, manifest.signer)
            with self.assertRaises(RootTrustError):
                trust.verify(forged_manifest, signature, minimum_generation=9)

    def test_official_runtime_fails_closed_when_root_key_is_unavailable(self):
        with tempfile.TemporaryDirectory(prefix="immune-missing-root-") as td:
            root = Path(td)
            manifest = root / "manifest.json"
            signature = root / "manifest.sig"
            manifest.write_text("{}", encoding="utf-8")
            signature.write_text("0" * 64, encoding="utf-8")
            db = root / "must-not-open.sqlite3"
            argv = [
                "--db", str(db),
                "--fortress-manifest", str(manifest),
                "--fortress-signature", str(signature),
                "--closed-lab-root",
                "--attest-only",
            ]
            clean = dict(os.environ)
            clean.pop("IMMUNE_FORTRESS_ROOT_KEY_HEX", None)
            with patch.dict(os.environ, clean, clear=True):
                self.assertEqual(immune_runtime_main(argv), CONTAINED_EXIT)
            self.assertFalse(db.exists())


if __name__ == "__main__":
    unittest.main()
