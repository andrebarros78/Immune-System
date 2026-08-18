from __future__ import annotations

from typing import Mapping, Sequence

from immune_execution_broker.isolation import ContainerSandboxRunner, SandboxIsolationError
from immune_fortress.adapter_manifest import AdapterManifestAuthority, SignedAdapterManifest


class AdapterSandboxError(RuntimeError):
    pass


class DisposableAdapterSandbox:
    """Ring-6 adapter host: signed manifest + capability allowlist + disposable sandbox."""

    def __init__(
        self,
        signed_manifest: SignedAdapterManifest,
        authority: AdapterManifestAuthority,
        runner: ContainerSandboxRunner | None = None,
    ) -> None:
        authority.verify(signed_manifest)
        self.signed_manifest = signed_manifest
        self.runner = runner or ContainerSandboxRunner()

    def run_json_probe(
        self,
        *,
        action: str,
        image_ref: str,
        command: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
        timeout: float = 20.0,
    ) -> dict:
        action = str(action).strip()
        if action not in set(self.signed_manifest.manifest.capabilities):
            raise AdapterSandboxError("adapter action outside signed manifest capability allowlist")
        try:
            actual_digest = self.runner.image_sha256(image_ref, timeout=timeout)
        except SandboxIsolationError as exc:
            raise AdapterSandboxError(f"adapter image attestation failed: {exc}") from exc
        expected_digest = self.signed_manifest.manifest.image_sha256.lower().removeprefix("sha256:")
        if actual_digest != expected_digest:
            raise AdapterSandboxError("adapter runtime image differs from signed manifest")
        try:
            return self.runner.run_json_probe(image_ref=image_ref, command=command, env=env, timeout=timeout)
        except SandboxIsolationError as exc:
            raise AdapterSandboxError(f"adapter sandbox containment failed: {exc}") from exc
