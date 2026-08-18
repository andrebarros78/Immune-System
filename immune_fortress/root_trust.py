from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol


class RootTrustError(RuntimeError):
    pass


class RootKeyProvider(Protocol):
    provider_id: str
    hardware_backed: bool

    def sign(self, payload: bytes) -> str: ...
    def verify(self, payload: bytes, signature: str) -> bool: ...


class ExternalHMACRootKey:
    """Closed-lab backend. Production deployment must replace it with hardware-backed trust."""

    provider_id = "external-hmac-lab"
    hardware_backed = False

    def __init__(self, secret: bytes):
        if len(secret) < 32:
            raise ValueError("root key must contain at least 32 bytes")
        self._secret = bytes(secret)

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), str(signature).lower())


@dataclass(frozen=True)
class RootManifest:
    generation: int
    source_commit: str
    files: dict[str, str]
    signer: str

    def canonical(self) -> bytes:
        value = {
            "generation": self.generation,
            "source_commit": self.source_commit,
            "files": self.files,
            "signer": self.signer,
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class BrainRootOfTrust:
    def __init__(self, root: str | Path, key_provider: RootKeyProvider):
        self.root = Path(root).resolve()
        self.key_provider = key_provider

    @staticmethod
    def _digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def build(self, paths: Iterable[str], *, generation: int, source_commit: str) -> tuple[RootManifest, str]:
        if generation < 1 or not source_commit.strip():
            raise RootTrustError("generation and source commit are required")
        files: dict[str, str] = {}
        for rel in sorted(set(paths)):
            path = (self.root / rel).resolve()
            if self.root not in path.parents:
                raise RootTrustError("manifest path escapes repository")
            if not path.is_file():
                raise RootTrustError(f"manifest file missing: {rel}")
            files[Path(rel).as_posix()] = self._digest(path)
        manifest = RootManifest(generation, source_commit, files, self.key_provider.provider_id)
        return manifest, self.key_provider.sign(manifest.canonical())

    def verify(self, manifest: RootManifest, signature: str, *, minimum_generation: int = 1) -> None:
        if manifest.generation < minimum_generation:
            raise RootTrustError("root manifest rollback detected")
        if not self.key_provider.verify(manifest.canonical(), signature):
            raise RootTrustError("root manifest signature invalid")
        for rel, expected in manifest.files.items():
            path = (self.root / rel).resolve()
            if self.root not in path.parents or not path.is_file():
                raise RootTrustError(f"root manifest integrity failure: {rel}")
            if not hmac.compare_digest(self._digest(path), expected):
                raise RootTrustError(f"root manifest integrity failure: {rel}")
