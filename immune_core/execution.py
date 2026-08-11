from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .audit import AuditLedger
from .checkpoints import CheckpointManager, CheckpointRef, WorkspaceManager
from .models import PolicyDecision, TaskLease
from .policy import PolicyGuard
from .privilege import PrivilegeAuthority
from .storage import SQLiteStateStore


class ExecutionError(RuntimeError):
    pass


class AuthorizationError(ExecutionError):
    pass


ACTIVE_EXECUTION_STATES = {"AUTHORIZED", "DISCOVERING", "RUNNING", "DEGRADED", "VALIDATING"}


@dataclass(frozen=True)
class WorkerManifest:
    id: str
    kinds: tuple[str, ...]
    capabilities: tuple[str, ...]
    authority: str
    allowed_executables: tuple[str, ...]
    max_runtime_seconds: float = 60.0
    max_output_bytes: int = 1_000_000
    env_allowlist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.kinds or not self.capabilities or not self.allowed_executables:
            raise ValueError("worker manifest requires identity, kinds, capabilities and executable allowlist")
        if self.authority not in {"task-scoped", "privileged-ephemeral"}:
            raise ValueError("invalid worker authority")
        if self.max_runtime_seconds <= 0 or self.max_output_bytes < 1024:
            raise ValueError("invalid worker limits")


@dataclass(frozen=True)
class ExecutionResult:
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    checkpoint_id: str | None
    rolled_back: bool
    policy_decision: str


class SafeExecutor:
    """No shell, task-bound cwd, minimal environment, timeout and policy gate."""

    def __init__(self, store: SQLiteStateStore, audit: AuditLedger, policy: PolicyGuard, workspaces: WorkspaceManager, checkpoints: CheckpointManager):
        self.store = store
        self.audit = audit
        self.policy = policy
        self.workspaces = workspaces
        self.checkpoints = checkpoints

    def _binding(self, lease: TaskLease, manifest: WorkerManifest) -> dict:
        if lease.lease_owner != manifest.id:
            raise AuthorizationError("worker does not own task lease")
        if lease.kind not in manifest.kinds:
            raise AuthorizationError("task kind outside worker manifest")
        mission = self.store.get_mission(lease.mission_id)
        if not mission:
            raise AuthorizationError("mission not found")
        if str(mission["state"]) not in ACTIVE_EXECUTION_STATES:
            raise AuthorizationError(f"mission state does not permit execution: {mission['state']}")
        return mission

    @staticmethod
    def _executable_name(argv0: str) -> str:
        return Path(argv0).name.casefold()

    def _validate_command(self, manifest: WorkerManifest, argv: Sequence[str]) -> tuple[str, ...]:
        if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
            raise ExecutionError("invalid argv")
        allowed = {Path(x).name.casefold() for x in manifest.allowed_executables}
        if self._executable_name(argv[0]) not in allowed:
            raise AuthorizationError("executable outside worker allowlist")
        return tuple(argv)

    @staticmethod
    def _environment(manifest: WorkerManifest, requested: Mapping[str, str] | None) -> dict[str, str]:
        base: dict[str, str] = {}
        for key in ("PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC"):
            value = os.environ.get(key)
            if value:
                base[key] = value
        requested = requested or {}
        allowed = set(manifest.env_allowlist)
        for key, value in requested.items():
            if key not in allowed:
                raise AuthorizationError(f"environment variable not allowlisted: {key}")
            base[str(key)] = str(value)
        return base

    @staticmethod
    def _truncate(value: str, limit: int) -> str:
        raw = value.encode("utf-8", errors="replace")
        if len(raw) <= limit:
            return value
        return raw[:limit].decode("utf-8", errors="replace") + "\n...[truncated]"

    def _policy_request(self, lease: TaskLease, *, scope: str, material_change: bool, checkpoint: CheckpointRef | None) -> dict:
        valid_checkpoint = bool(checkpoint and self.checkpoints.verify(checkpoint))
        return {"mission_id": lease.mission_id, "action": "execute_task", "required_scope": scope, "mission_authorized": True, "system_authorized": True, "scope_ok": True, "material_change": bool(material_change), "checkpoint_valid": valid_checkpoint, "irreversible": False, "recovery_verified": valid_checkpoint}

    def _execute(self, lease: TaskLease, manifest: WorkerManifest, worker_token: str, argv: Sequence[str], *, scope: str, checkpoint: CheckpointRef | None, material_change: bool, timeout_seconds: float | None, env: Mapping[str, str] | None, now: int | None, privilege: tuple[PrivilegeAuthority, str, str] | None = None) -> ExecutionResult:
        self._binding(lease, manifest)
        command = self._validate_command(manifest, argv)
        workspace = self.workspaces.for_task(lease.mission_id, lease.id)
        if material_change and checkpoint is None:
            checkpoint = self.checkpoints.create(workspace, lease.mission_id, lease.id)
        decision: PolicyDecision = self.policy.evaluate_token(worker_token, self._policy_request(lease, scope=scope, material_change=material_change, checkpoint=checkpoint), now=now)
        if not decision.permitted:
            raise AuthorizationError(f"PolicyGuard: {decision.decision}: {decision.reason}")
        if privilege is not None:
            authority, grant_token, action = privilege
            if manifest.authority != "privileged-ephemeral":
                raise AuthorizationError("worker manifest has no privileged authority")
            if checkpoint is None or not self.checkpoints.verify(checkpoint):
                raise AuthorizationError("privileged execution requires verified checkpoint")
            authority.consume(grant_token, mission_id=lease.mission_id, task_id=lease.id, worker_id=manifest.id, action=action, checkpoint_id=checkpoint.id, now=now)
        timeout = min(float(timeout_seconds if timeout_seconds is not None else manifest.max_runtime_seconds), float(manifest.max_runtime_seconds))
        if timeout <= 0:
            raise ExecutionError("timeout must be positive")
        started = time.monotonic()
        rolled_back = False
        try:
            completed = subprocess.run(command, cwd=workspace, env=self._environment(manifest, env), shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False)
            returncode = int(completed.returncode)
            stdout = self._truncate(completed.stdout or "", manifest.max_output_bytes)
            stderr = self._truncate(completed.stderr or "", manifest.max_output_bytes)
        except subprocess.TimeoutExpired as exc:
            returncode = 124
            stdout = self._truncate(exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""), manifest.max_output_bytes)
            stderr = self._truncate(exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""), manifest.max_output_bytes)
        if returncode != 0 and checkpoint is not None and material_change:
            self.checkpoints.restore(checkpoint, workspace)
            rolled_back = True
        duration = time.monotonic() - started
        self.audit.append(actor=manifest.id, action="privileged_execution" if privilege else "safe_execution", mission_id=lease.mission_id, payload={"task_id": lease.id, "executable": Path(command[0]).name, "argument_count": max(0, len(command) - 1), "returncode": returncode, "duration_seconds": duration, "checkpoint_id": checkpoint.id if checkpoint else None, "rolled_back": rolled_back, "policy_decision": decision.decision})
        return ExecutionResult(returncode, stdout, stderr, duration, checkpoint.id if checkpoint else None, rolled_back, decision.decision)

    def run(self, lease: TaskLease, manifest: WorkerManifest, worker_token: str, argv: Sequence[str], *, material_change: bool = False, timeout_seconds: float | None = None, env: Mapping[str, str] | None = None, now: int | None = None) -> ExecutionResult:
        return self._execute(lease, manifest, worker_token, argv, scope="execute:safe", checkpoint=None, material_change=material_change, timeout_seconds=timeout_seconds, env=env, now=now)


class PrivilegedExecutor(SafeExecutor):
    """Sovereign privilege boundary. It never performs sudo/UAC bypass or self-elevation."""

    def run_privileged(self, lease: TaskLease, manifest: WorkerManifest, worker_token: str, argv: Sequence[str], *, privilege_authority: PrivilegeAuthority, grant_token: str, action: str, checkpoint: CheckpointRef, timeout_seconds: float | None = None, env: Mapping[str, str] | None = None, now: int | None = None) -> ExecutionResult:
        if action not in manifest.capabilities:
            raise AuthorizationError("privileged action outside worker capability")
        return self._execute(lease, manifest, worker_token, argv, scope="execute:privileged", checkpoint=checkpoint, material_change=True, timeout_seconds=timeout_seconds, env=env, now=now, privilege=(privilege_authority, grant_token, action))
