from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .audit import AuditLedger
from .engine import DurableLoopEngine
from .storage import SQLiteStateStore


class DispatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class ControlledAction:
    action_id: str
    task_kind: str
    argv: tuple[str, ...]
    material_change: bool = False
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not self.action_id.strip() or not self.task_kind.strip() or not self.argv:
            raise ValueError("controlled action requires id, task kind and argv")
        if self.timeout_seconds <= 0:
            raise ValueError("controlled action timeout must be positive")


@dataclass(frozen=True)
class DispatchOutcome:
    operator_task_id: str | None
    state: str
    child_task_id: str | None = None
    detail: str = ""


class RunbookActionRegistry:
    """Trusted Core-side mapping. Operators select a logical target, never argv."""

    def __init__(self, actions: Mapping[tuple[str, str], ControlledAction]):
        normalized: dict[tuple[str, str], ControlledAction] = {}
        for (runbook_id, target_id), action in actions.items():
            key = (str(runbook_id).strip(), str(target_id).strip())
            if not all(key):
                raise ValueError("runbook and target ids are required")
            normalized[key] = action
        self._actions = normalized

    def resolve(self, runbook_id: str, target_id: str) -> ControlledAction:
        action = self._actions.get((str(runbook_id).strip(), str(target_id).strip()))
        if action is None:
            raise DispatchError("runbook target is not registered by Core")
        return action


class OperatorCommandDispatcher:
    """Transforms a policy-approved operator command into a closed durable task.

    It never executes host commands. Executable argv is supplied only by the
    trusted RunbookActionRegistry configured by Core.
    """

    def __init__(
        self,
        store: SQLiteStateStore,
        engine: DurableLoopEngine,
        registry: RunbookActionRegistry,
        audit: AuditLedger,
        *,
        dispatcher_id: str = "operator-dispatcher",
    ):
        self.store = store
        self.engine = engine
        self.registry = registry
        self.audit = audit
        self.dispatcher_id = dispatcher_id

    def run_once(self, *, now: float | None = None) -> DispatchOutcome:
        lease = self.engine.claim_next(self.dispatcher_id, now=now)
        if lease is None:
            return DispatchOutcome(None, "IDLE")
        if lease.kind != "operator_command":
            self.engine.fail_task(lease, "dispatcher received non-operator task", retry_delay=0, now=now)
            return DispatchOutcome(lease.id, "REJECTED", detail="non-operator task")

        payload = lease.payload
        command_id = str(payload.get("operator_command_id", "")).strip()
        action = str(payload.get("action", "")).strip().lower()
        target = str(payload.get("target", "")).strip()
        parameters = payload.get("parameters")
        if not command_id or not isinstance(parameters, dict):
            self.engine.block_task(lease, "malformed operator command", now=now)
            return DispatchOutcome(lease.id, "BLOCKED", detail="malformed operator command")

        row = self.store.conn.execute(
            "SELECT * FROM op_commands WHERE id=? AND task_id=?",
            (command_id, lease.id),
        ).fetchone()
        if row is None or str(row["state"]) != "QUEUED":
            self.engine.block_task(lease, "operator command record is missing or not queued", now=now)
            return DispatchOutcome(lease.id, "BLOCKED", detail="operator command state mismatch")

        try:
            if action != "diagnose" or target != "service-recovery":
                raise DispatchError("dispatcher supports only registered service-recovery in Phase 9")
            if str(parameters.get("runbook", "")).strip() != "service-recovery":
                raise DispatchError("runbook identity mismatch")
            service_id = str(parameters.get("service", "")).strip()
            controlled = self.registry.resolve("service-recovery", service_id)
        except DispatchError as exc:
            self.engine.block_task(lease, str(exc), now=now)
            self.store.conn.execute("UPDATE op_commands SET state='BLOCKED' WHERE id=?", (command_id,))
            self.audit.append(
                actor=self.dispatcher_id,
                action="operator_command_blocked",
                mission_id=lease.mission_id,
                payload={"operator_command_id": command_id, "reason": str(exc)},
                now=now,
            )
            return DispatchOutcome(lease.id, "BLOCKED", detail=str(exc))

        child_id = self.engine.submit_task(
            lease.mission_id,
            controlled.task_kind,
            {
                "mode": "safe",
                "argv": list(controlled.argv),
                "material_change": bool(controlled.material_change),
                "timeout_seconds": float(controlled.timeout_seconds),
                "source_operator_command_id": command_id,
            },
            idempotency_key=f"operator-dispatch:{command_id}:{controlled.action_id}",
            priority=90,
            max_attempts=1,
            now=now,
        )
        self.engine.complete_task(lease, now=now)
        self.store.conn.execute("UPDATE op_commands SET state='DISPATCHED' WHERE id=?", (command_id,))
        self.audit.append(
            actor=self.dispatcher_id,
            action="operator_command_dispatched",
            mission_id=lease.mission_id,
            payload={
                "operator_command_id": command_id,
                "controlled_action_id": controlled.action_id,
                "child_task_id": child_id,
                "task_kind": controlled.task_kind,
            },
            now=now,
        )
        return DispatchOutcome(lease.id, "DISPATCHED", child_id)
