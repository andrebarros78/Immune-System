from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .audit import AuditLedger
from .state_backup import BackupRef, StateBackupManager


class UpdateError(RuntimeError):
    pass


@dataclass(frozen=True)
class StagedRelease:
    id: str
    version: str
    path: str
    manifest_sha256: str


@dataclass(frozen=True)
class ActivationResult:
    version: str
    active: bool
    rolled_back: bool
    backup_id: str
    previous_version: str | None


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class ReleaseManager:
    """Local staged release activation with integrity gate and atomic pointer rollback."""

    MANIFEST = "release-manifest.json"

    def __init__(self, root: str | Path, backups: StateBackupManager, audit: AuditLedger):
        self.root = Path(root).resolve()
        self.staging = self.root / "staging"
        self.releases = self.root / "releases"
        self.pointer = self.root / "current.json"
        self.staging.mkdir(parents=True, exist_ok=True)
        self.releases.mkdir(parents=True, exist_ok=True)
        self.backups = backups
        self.audit = audit

    @staticmethod
    def _version_tuple(value: str) -> tuple[int, ...]:
        parts = value.strip().split(".")
        if not parts or any(not p.isdigit() for p in parts):
            raise UpdateError("release version must be numeric dotted form")
        return tuple(int(p) for p in parts)

    @staticmethod
    def build_manifest(source: str | Path, version: str) -> dict:
        src = Path(source).resolve()
        files: dict[str, str] = {}
        for path in sorted(src.rglob("*")):
            if path.is_symlink():
                raise UpdateError("symlinks are forbidden in release bundles")
            if not path.is_file() or path.name == ReleaseManager.MANIFEST:
                continue
            rel = path.relative_to(src).as_posix()
            files[rel] = _hash_file(path)
        if not files:
            raise UpdateError("release bundle is empty")
        return {"schema": 1, "version": version, "files": files}

    @classmethod
    def write_manifest(cls, source: str | Path, version: str) -> Path:
        cls._version_tuple(version)
        src = Path(source).resolve()
        manifest = cls.build_manifest(src, version)
        target = src / cls.MANIFEST
        target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return target

    @staticmethod
    def _verify_tree(root: Path, manifest: dict) -> bool:
        if manifest.get("schema") != 1 or not isinstance(manifest.get("files"), dict):
            return False
        expected = dict(manifest["files"])
        actual: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                return False
            if not path.is_file() or path.name == ReleaseManager.MANIFEST:
                continue
            rel = path.relative_to(root).as_posix()
            actual[rel] = _hash_file(path)
        return actual == expected

    def current(self) -> dict | None:
        if not self.pointer.exists():
            return None
        try:
            data = json.loads(self.pointer.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise UpdateError("current release pointer is invalid") from exc
        return data

    def stage(self, source: str | Path) -> StagedRelease:
        src = Path(source).resolve()
        manifest_path = src / self.MANIFEST
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise UpdateError("release manifest unavailable") from exc
        version = str(manifest.get("version", ""))
        self._version_tuple(version)
        if not self._verify_tree(src, manifest):
            raise UpdateError("release bundle integrity failed")
        current = self.current()
        if current is not None and self._version_tuple(version) <= self._version_tuple(str(current["version"])):
            raise UpdateError("release version must advance monotonically")
        stage_id = uuid.uuid4().hex
        dst = self.staging / stage_id
        shutil.copytree(src, dst)
        if not self._verify_tree(dst, manifest):
            shutil.rmtree(dst, ignore_errors=True)
            raise UpdateError("staged release verification failed")
        manifest_sha = hashlib.sha256(_canonical(manifest)).hexdigest()
        self.audit.append(actor="release-manager", action="release_staged", payload={"stage_id": stage_id, "version": version, "manifest_sha256": manifest_sha})
        return StagedRelease(stage_id, version, str(dst), manifest_sha)

    def _write_pointer(self, payload: dict) -> None:
        tmp = self.root / f".current.{uuid.uuid4().hex}.tmp"
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.pointer)

    def activate(self, staged: StagedRelease, health_check: Callable[[Path], bool], *, now: float | None = None) -> ActivationResult:
        when = time.time() if now is None else float(now)
        stage_path = Path(staged.path).resolve()
        if self.staging not in stage_path.parents or not stage_path.is_dir():
            raise UpdateError("staged release escaped root")
        manifest = json.loads((stage_path / self.MANIFEST).read_text(encoding="utf-8"))
        if str(manifest.get("version")) != staged.version or not self._verify_tree(stage_path, manifest):
            raise UpdateError("staged release changed after verification")

        previous = self.current()
        backup: BackupRef = self.backups.create(now=when)
        if not self.backups.verify(backup):
            raise UpdateError("pre-update state backup failed verification")

        release_path = self.releases / staged.version
        if release_path.exists():
            raise UpdateError("release version already installed")
        shutil.copytree(stage_path, release_path)
        pointer = {"version": staged.version, "path": str(release_path), "activated_at": when, "backup_id": backup.id}
        self._write_pointer(pointer)

        healthy = False
        try:
            healthy = bool(health_check(release_path))
        except Exception:
            healthy = False
        if not healthy:
            if previous is None:
                self.pointer.unlink(missing_ok=True)
            else:
                self._write_pointer(previous)
            shutil.rmtree(release_path, ignore_errors=True)
            self.audit.append(actor="release-manager", action="release_activation_rolled_back", payload={"version": staged.version, "backup_id": backup.id, "previous_version": previous.get("version") if previous else None}, now=when)
            return ActivationResult(staged.version, False, True, backup.id, str(previous["version"]) if previous else None)

        self.audit.append(actor="release-manager", action="release_activated", payload={"version": staged.version, "backup_id": backup.id, "previous_version": previous.get("version") if previous else None}, now=when)
        return ActivationResult(staged.version, True, False, backup.id, str(previous["version"]) if previous else None)

    def rollback_to(self, version: str, *, now: float | None = None) -> dict:
        release_path = (self.releases / version).resolve()
        if self.releases not in release_path.parents or not release_path.is_dir():
            raise UpdateError("rollback release is unavailable")
        manifest = json.loads((release_path / self.MANIFEST).read_text(encoding="utf-8"))
        if not self._verify_tree(release_path, manifest):
            raise UpdateError("rollback release failed integrity verification")
        when = time.time() if now is None else float(now)
        payload = {"version": version, "path": str(release_path), "activated_at": when, "rollback": True}
        self._write_pointer(payload)
        self.audit.append(actor="release-manager", action="release_rollback", payload={"version": version}, now=when)
        return payload
