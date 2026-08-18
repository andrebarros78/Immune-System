from __future__ import annotations

from dataclasses import dataclass

from .root_trust import BrainRootOfTrust, RootManifest, RootTrustError


@dataclass(frozen=True)
class BootAttestation:
    mode: str
    operational: bool
    reason: str
    generation: int
    signer: str
    hardware_backed: bool


class FortressBootGate:
    """Fail-closed boot gate for the sovereign brain.

    A failed root attestation never falls back to operational mode. A physical
    deployment can additionally require a hardware-backed root provider.
    """

    def __init__(self, trust: BrainRootOfTrust):
        self.trust = trust

    def attest(
        self,
        manifest: RootManifest,
        signature: str,
        *,
        minimum_generation: int = 1,
        require_hardware_backed: bool = False,
    ) -> BootAttestation:
        if require_hardware_backed and not bool(self.trust.key_provider.hardware_backed):
            return BootAttestation(
                "CONTAINED_READ_ONLY",
                False,
                "hardware-backed root of trust required",
                manifest.generation,
                manifest.signer,
                False,
            )
        try:
            self.trust.verify(manifest, signature, minimum_generation=minimum_generation)
        except RootTrustError as exc:
            return BootAttestation(
                "CONTAINED_READ_ONLY",
                False,
                str(exc),
                manifest.generation,
                manifest.signer,
                bool(self.trust.key_provider.hardware_backed),
            )
        return BootAttestation(
            "OPERATIONAL",
            True,
            "root attestation verified",
            manifest.generation,
            manifest.signer,
            bool(self.trust.key_provider.hardware_backed),
        )
