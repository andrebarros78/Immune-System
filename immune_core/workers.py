from __future__ import annotations

from dataclasses import dataclass

from .checkpoints import CheckpointManager, WorkspaceManager
from .engine import DurableLoopEngine
from .execution import AuthorizationError, ExecutionError, PrivilegedExecutor, SafeExecutor, WorkerManifest
from .privilege import PrivilegeAuthority, PrivilegeError


@dataclass(frozen=True)
class WorkerOutcome:
    task_id: str | None
    state: str
    returncode: int | None = None
    rolled_back: bool = False
    detail: str = ""


class WorkerRunner:
    """Claims durable tasks and binds execution to lease, manifest, identity, policy and checkpoint."""

    def __init__(self, engine: DurableLoopEngine, safe_executor: SafeExecutor, privileged_executor: PrivilegedExecutor, workspaces: WorkspaceManager, checkpoints: CheckpointManager, privilege_authority: PrivilegeAuthority):
        self.engine = engine
        self.safe_executor = safe_executor
        self.privileged_executor = privileged_executor
        self.workspaces = workspaces
        self.checkpoints = checkpoints
        self.privilege_authority = privilege_authority

    def run_once(
        self,
        manifest: WorkerManifest,
        worker_token: str,
        *,
        privilege_authorizer_token: str | None = None,
        now: int | None = None,
        mission_id: str | None = None,
    ) -> WorkerOutcome:
        lease = self.engine.claim_next(
            manifest.id,
            now=float(now) if now is not None else None,
            mission_id=mission_id,
        )
        if lease is None:
            return WorkerOutcome(None, "IDLE")
        payload = lease.payload
        try:
            if lease.kind not in manifest.kinds:
                raise AuthorizationError("task kind outside worker manifest")
            mode = str(payload.get("mode", "safe"))
            argv = payload.get("argv")
            if not isinstance(argv, list) or not argv:
                raise ExecutionError("task payload requires argv list")
            if mode == "safe":
                result = self.safe_executor.run(lease, manifest, worker_token, argv, material_change=bool(payload.get("material_change", False)), timeout_seconds=payload.get("timeout_seconds"), env=payload.get("env"), now=now)
            elif mode == "privileged":
                if privilege_authorizer_token is None:
                    raise AuthorizationError("privileged task requires external authorizer identity")
                action = str(payload.get("action", "")).strip()
                if not action:
                    raise AuthorizationError("privileged task requires exact action")
                workspace = self.workspaces.for_task(lease.mission_id, lease.id)
                checkpoint = self.checkpoints.create(workspace, lease.mission_id, lease.id)
                grant = self.privilege_authority.issue(privilege_authorizer_token, mission_id=lease.mission_id, task_id=lease.id, worker_id=manifest.id, action=action, checkpoint_id=checkpoint.id, now=now)
                result = self.privileged_executor.run_privileged(lease, manifest, worker_token, argv, privilege_authority=self.privilege_authority, grant_token=grant.token, action=action, checkpoint=checkpoint, timeout_seconds=payload.get("timeout_seconds"), env=payload.get("env"), now=now)
            else:
                raise AuthorizationError("unknown execution mode")
        except (AuthorizationError, PrivilegeError) as exc:
            self.engine.block_task(lease, str(exc), now=float(now) if now is not None else None)
            return WorkerOutcome(lease.id, "BLOCKED", detail=str(exc))
        except ExecutionError as exc:
            state = self.engine.fail_task(lease, str(exc), now=float(now) if now is not None else None)
            return WorkerOutcome(lease.id, state, detail=str(exc))
        if result.returncode == 0:
            self.engine.complete_task(lease, now=float(now) if now is not None else None)
            return WorkerOutcome(lease.id, "COMPLETED", 0, result.rolled_back)
        state = self.engine.fail_task(lease, f"process exited with {result.returncode}", now=float(now) if now is not None else None)
        return WorkerOutcome(lease.id, state, result.returncode, result.rolled_back, f"process exited with {result.returncode}")
