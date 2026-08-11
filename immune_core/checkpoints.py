from __future__ import annotations

import hashlib
import json
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLedger


class CheckpointError(RuntimeError):
    pass


@dataclass(frozen=True)
class CheckpointRef:
    id: str
    mission_id: str
    task_id: str
    path: str
    manifest_sha256: str


def _safe_component(value: str) -> str:
    if not value:
        raise CheckpointError("empty scope identifier")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class WorkspaceManager:
    """Derives workspaces from mission/task identity; callers cannot choose arbitrary cwd."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def for_task(self, mission_id: str, task_id: str) -> Path:
        path = self.root / _safe_component(mission_id) / _safe_component(task_id)
        path.mkdir(parents=True, exist_ok=True)
        resolved = path.resolve()
        if self.root not in resolved.parents:
            raise CheckpointError("workspace escaped root")
        return resolved

    def contains(self, path: str | Path) -> bool:
        resolved = Path(path).resolve()
        return resolved == self.root or self.root in resolved.parents


class CheckpointManager:
    """Filesystem checkpoints with content hashes and verified rollback."""

    def __init__(self, root: str | Path, workspaces: WorkspaceManager, audit: AuditLedger):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.workspaces = workspaces
        self.audit = audit

    @staticmethod
    def _inventory(data_root: Path) -> list[dict[str, Any]]:
        inventory: list[dict[str, Any]] = []
        if not data_root.exists():
            return inventory
        for path in sorted(data_root.rglob("*")):
            rel = path.relative_to(data_root).as_posix()
            if path.is_symlink():
                raise CheckpointError(f"symlink not permitted in checkpoint: {rel}")
            if path.is_file():
                inventory.append({"path": rel, "size": path.stat().st_size, "sha256": _hash_file(path)})
        return inventory

    def create(self, workspace: str | Path, mission_id: str, task_id: str, *, now: float | None = None) -> CheckpointRef:
        ws = Path(workspace).resolve()
        if not self.workspaces.contains(ws):
            raise CheckpointError("workspace outside managed root")
        checkpoint_id = str(uuid.uuid4())
        cp_dir = self.root / checkpoint_id
        data_dir = cp_dir / "data"
        cp_dir.mkdir(parents=True, exist_ok=False)
        if ws.exists():
            shutil.copytree(ws, data_dir, symlinks=False, dirs_exist_ok=True)
        else:
            data_dir.mkdir()
        inventory = self._inventory(data_dir)
        manifest = {
            "schema": 1,
            "id": checkpoint_id,
            "mission_id": mission_id,
            "task_id": task_id,
            "created_at": time.time() if now is None else float(now),
            "inventory": inventory,
        }
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        manifest_sha = hashlib.sha256(canonical).hexdigest()
        (cp_dir / "manifest.json").write_text(json.dumps({**manifest, "manifest_sha256": manifest_sha}, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        self.audit.append(actor="checkpoint-manager", action="checkpoint_created", mission_id=mission_id, payload={"checkpoint_id": checkpoint_id, "task_id": task_id, "manifest_sha256": manifest_sha})
        return CheckpointRef(checkpoint_id, mission_id, task_id, str(cp_dir), manifest_sha)

    def get(self, checkpoint_id: str) -> CheckpointRef:
        cp_dir = (self.root / checkpoint_id).resolve()
        if self.root not in cp_dir.parents:
            raise CheckpointError("checkpoint escaped root")
        manifest_path = cp_dir / "manifest.json"
        if not manifest_path.exists():
            raise CheckpointError("checkpoint not found")
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return CheckpointRef(str(data["id"]), str(data["mission_id"]), str(data["task_id"]), str(cp_dir), str(data["manifest_sha256"]))

    def verify(self, checkpoint: CheckpointRef) -> bool:
        cp_dir = Path(checkpoint.path).resolve()
        if self.root not in cp_dir.parents:
            return False
        manifest_path = cp_dir / "manifest.json"
        data_dir = cp_dir / "data"
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected_manifest_sha = raw.pop("manifest_sha256")
            canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if hashlib.sha256(canonical).hexdigest() != expected_manifest_sha:
                return False
            if expected_manifest_sha != checkpoint.manifest_sha256:
                return False
            actual = self._inventory(data_dir)
            return actual == raw.get("inventory", [])
        except (OSError, ValueError, KeyError, CheckpointError, json.JSONDecodeError):
            return False

    @staticmethod
    def _clear_workspace(workspace: Path) -> None:
        if not workspace.exists():
            workspace.mkdir(parents=True, exist_ok=True)
            return
        for child in list(workspace.iterdir()):
            if child.is_symlink() or child.is_file():
                child.unlink()
            elif child.is_dir():
                shutil.rmtree(child)

    def restore(self, checkpoint: CheckpointRef, workspace: str | Path) -> None:
        ws = Path(workspace).resolve()
        if not self.workspaces.contains(ws):
            raise CheckpointError("workspace outside managed root")
        if not self.verify(checkpoint):
            raise CheckpointError("checkpoint integrity verification failed")
        cp_dir = Path(checkpoint.path)
        self._clear_workspace(ws)
        shutil.copytree(cp_dir / "data", ws, dirs_exist_ok=True)
        self.audit.append(actor="checkpoint-manager", action="checkpoint_restored", mission_id=checkpoint.mission_id, payload={"checkpoint_id": checkpoint.id, "task_id": checkpoint.task_id})
