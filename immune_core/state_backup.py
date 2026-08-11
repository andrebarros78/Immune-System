from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLedger
from .storage import SQLiteStateStore


class BackupError(RuntimeError):
    pass


@dataclass(frozen=True)
class BackupRef:
    id: str
    path: str
    manifest_path: str
    sha256: str
    created_at: float


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class StateBackupManager:
    """Consistent SQLite backup, verification and restore primitive."""

    def __init__(self, store: SQLiteStateStore, root: str | Path, audit: AuditLedger):
        self.store = store
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.audit = audit

    @staticmethod
    def _integrity(path: Path) -> bool:
        try:
            conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=30)
            try:
                row = conn.execute("PRAGMA integrity_check").fetchone()
                return bool(row and str(row[0]).lower() == "ok")
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    def create(self, *, now: float | None = None) -> BackupRef:
        when = time.time() if now is None else float(now)
        backup_id = str(uuid.uuid4())
        backup_path = self.root / f"{backup_id}.sqlite3"
        manifest_path = self.root / f"{backup_id}.json"

        destination = sqlite3.connect(str(backup_path))
        try:
            self.store.conn.backup(destination)
        finally:
            destination.close()
        if not self._integrity(backup_path):
            backup_path.unlink(missing_ok=True)
            raise BackupError("created backup failed integrity_check")

        digest = _hash_file(backup_path)
        manifest = {
            "schema": 1,
            "id": backup_id,
            "created_at": when,
            "sha256": digest,
            "size": backup_path.stat().st_size,
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.audit.append(
            actor="state-backup-manager",
            action="state_backup_created",
            payload={"backup_id": backup_id, "sha256": digest, "size": manifest["size"]},
            now=when,
        )
        return BackupRef(backup_id, str(backup_path), str(manifest_path), digest, when)

    def get(self, backup_id: str) -> BackupRef:
        manifest_path = (self.root / f"{backup_id}.json").resolve()
        if self.root not in manifest_path.parents:
            raise BackupError("backup manifest escaped root")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BackupError("backup manifest unavailable") from exc
        backup_path = (self.root / f"{backup_id}.sqlite3").resolve()
        return BackupRef(str(manifest["id"]), str(backup_path), str(manifest_path), str(manifest["sha256"]), float(manifest["created_at"]))

    def verify(self, ref: BackupRef) -> bool:
        path = Path(ref.path).resolve()
        manifest_path = Path(ref.manifest_path).resolve()
        if self.root not in path.parents or self.root not in manifest_path.parents:
            return False
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if str(manifest["id"]) != ref.id or str(manifest["sha256"]) != ref.sha256:
                return False
            if not path.is_file() or path.stat().st_size != int(manifest["size"]):
                return False
            if _hash_file(path) != ref.sha256:
                return False
            return self._integrity(path)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return False

    def restore_to(self, ref: BackupRef, target: str | Path, *, now: float | None = None) -> Path:
        if not self.verify(ref):
            raise BackupError("backup verification failed")
        target_path = Path(target).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target_path.with_name(f".{target_path.name}.{uuid.uuid4().hex}.restore")
        shutil.copy2(ref.path, tmp_path)
        if _hash_file(tmp_path) != ref.sha256 or not self._integrity(tmp_path):
            tmp_path.unlink(missing_ok=True)
            raise BackupError("restored copy failed verification")
        os.replace(tmp_path, target_path)
        when = time.time() if now is None else float(now)
        self.audit.append(
            actor="state-backup-manager",
            action="state_backup_restored",
            payload={"backup_id": ref.id, "target_name": target_path.name, "sha256": ref.sha256},
            now=when,
        )
        return target_path
