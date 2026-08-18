from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass


class AdapterManifestError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdapterManifest:
    adapter_id: str
    version: str
    image_sha256: str
    capabilities: tuple[str, ...]
    execution_mode: str = "container-disposable"
    network_policy: str = "deny-by-default"

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "adapter_id": self.adapter_id,
                "version": self.version,
                "image_sha256": self.image_sha256,
                "capabilities": sorted(set(self.capabilities)),
                "execution_mode": self.execution_mode,
                "network_policy": self.network_policy,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


@dataclass(frozen=True)
class SignedAdapterManifest:
    manifest: AdapterManifest
    signature: str
    signer: str


class AdapterManifestAuthority:
    """Independent closed-lab signer/verifier for disposable adapter manifests."""

    def __init__(self, secret: bytes, *, signer: str = "immune-adapter-manifest") -> None:
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
            raise ValueError("adapter manifest key must contain at least 32 bytes")
        self._secret = bytes(secret)
        self.signer = signer

    @staticmethod
    def validate(manifest: AdapterManifest) -> None:
        if not manifest.adapter_id.strip() or not manifest.version.strip() or not manifest.capabilities:
            raise AdapterManifestError("adapter manifest identity/version/capabilities required")
        digest = manifest.image_sha256.lower().removeprefix("sha256:")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise AdapterManifestError("adapter image_sha256 must be an exact sha256 digest")
        if manifest.execution_mode != "container-disposable":
            raise AdapterManifestError("adapter must execute as a disposable container")
        if manifest.network_policy != "deny-by-default":
            raise AdapterManifestError("adapter network policy must be deny-by-default")

    def sign(self, manifest: AdapterManifest) -> SignedAdapterManifest:
        self.validate(manifest)
        signature = hmac.new(self._secret, manifest.canonical(), hashlib.sha256).hexdigest()
        return SignedAdapterManifest(manifest, signature, self.signer)

    def verify(self, signed: SignedAdapterManifest) -> None:
        if signed.signer != self.signer:
            raise AdapterManifestError("adapter manifest signer mismatch")
        self.validate(signed.manifest)
        expected = hmac.new(self._secret, signed.manifest.canonical(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(signed.signature).lower()):
            raise AdapterManifestError("adapter manifest signature invalid")
