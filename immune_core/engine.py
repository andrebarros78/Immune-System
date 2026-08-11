from __future__ import annotations

from typing import Any

from .audit import AuditLedger
from .models import TaskLease
from .storage import SQLiteStateStore, StateError


MISSION_TRANSITIONS: dict[str, set[str]] = {
    "CREATED": {"AUTHORIZED", "CANCELLED"},
    "AUTHORIZED": {"DISCOVERING", "RUNNING", "CANCELLED", "FAILED_SAFE"},
    "DISCOVERING": {"RUNNING", "DEGRADED", "BLOCKED", "FAILED_SAFE", "CANCELLED"},
    "RUNNING": {"DEGRADED", "BLOCKED", "WAITING_HUMAN", "CONTAINED", "VALIDATING", "FAILED_SAFE", "CANCELLED"},
    "DEGRADED": {"RUNNING", "BLOCKED", "WAITING_HUMAN", "CONTAINED", "VALIDATING", "FAILED_SAFE", "CANCELLED"},
    "BLOCKED": {"RUNNING", "WAITING_HUMAN", "CONTAINED", "FAILED_SAFE", "CANCELLED"},
    "WAITING_HUMAN": {"RUNNING", "CONTAINED", "FAILED_SAFE", "CANCELLED"},
    "CONTAINED": {"RUNNING", "WAITING_HUMAN", "VALIDATING", "FAILED_SAFE", "CANCELLED"},
    "VALIDATING": {"RUNNING", "DEGRADED", "COMPLETED", "FAILED_SAFE"},
    "COMPLETED": set(),
    "FAILED_SAFE": {"RUNNING", "CANCELLED"},
    "CANCELLED": set(),
}


class DurableLoopEngine:
    """Motor durável mínimo da missão: estado, fila, lease, retry e retomada."""

    def __init__(self, store: SQLiteStateStore, audit: AuditLedger):
        self.store = store
        self.audit = audit

    def create_mission(self, mission_id: str, system_id: str) -> None:
        self.store.create_mission(mission_id, system_id)
        self.audit.append(actor="sovereign-engine", action="mission_created", mission_id=mission_id, payload={"system_id": system_id})

    def transition_mission(
        self,
        mission_id: str,
        to_state: str,
        reason: str,
        *,
        mission_proven: bool = False,
    ) -> None:
        current = self.store.get_mission(mission_id)
        if not current:
            raise StateError("mission not found")
        from_state = str(current["state"])
        if to_state not in MISSION_TRANSITIONS.get(from_state, set()):
            raise StateError(f"invalid mission transition {from_state}->{to_state}")
        if to_state == "COMPLETED" and not mission_proven:
            raise StateError("COMPLETED requires MISSION_PROVEN")
        self.store.set_mission_state(mission_id, to_state, reason)
        self.audit.append(
            actor="sovereign-engine",
            action="mission_transition",
            mission_id=mission_id,
            payload={"from": from_state, "to": to_state, "reason": reason, "mission_proven": mission_proven},
        )

    def submit_task(
        self,
        mission_id: str,
        kind: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        priority: int = 0,
        max_attempts: int = 3,
        now: float | None = None,
    ) -> str:
        task_id = self.store.submit_task(
            mission_id,
            kind,
            payload,
            idempotency_key=idempotency_key,
            priority=priority,
            max_attempts=max_attempts,
            now=now,
        )
        self.audit.append(
            actor="sovereign-engine",
            action="task_submitted",
            mission_id=mission_id,
            payload={"task_id": task_id, "kind": kind, "idempotency_key": idempotency_key},
        )
        return task_id

    def claim_next(self, worker_id: str, *, lease_seconds: float = 30, now: float | None = None) -> TaskLease | None:
        lease = self.store.claim_next(worker_id, lease_seconds=lease_seconds, now=now)
        if lease:
            self.audit.append(
                actor=worker_id,
                action="task_claimed",
                mission_id=lease.mission_id,
                payload={"task_id": lease.id, "attempt": lease.attempts, "lease_until": lease.lease_until},
            )
        return lease

    def complete_task(self, lease: TaskLease, *, now: float | None = None) -> None:
        self.store.complete_task(lease.id, lease.lease_owner, now=now)
        self.audit.append(
            actor=lease.lease_owner,
            action="task_completed",
            mission_id=lease.mission_id,
            payload={"task_id": lease.id, "attempt": lease.attempts},
        )

    def fail_task(self, lease: TaskLease, error: str, *, retry_delay: float = 0, now: float | None = None) -> str:
        state = self.store.fail_task(
            lease.id,
            lease.lease_owner,
            error,
            retry_delay=retry_delay,
            now=now,
        )
        self.audit.append(
            actor=lease.lease_owner,
            action="task_failed",
            mission_id=lease.mission_id,
            payload={"task_id": lease.id, "attempt": lease.attempts, "error": error, "next_state": state},
        )
        return state

    def block_task(self, lease: TaskLease, reason: str, *, now: float | None = None) -> None:
        self.store.block_task(lease.id, lease.lease_owner, reason, now=now)
        self.audit.append(
            actor=lease.lease_owner,
            action="task_blocked",
            mission_id=lease.mission_id,
            payload={"task_id": lease.id, "reason": reason},
        )

    def resume(self, *, now: float | None = None) -> dict[str, int]:
        recovered = self.store.recover_expired_leases(now=now)
        rows = self.store.conn.execute(
            "SELECT state, COUNT(*) AS n FROM tasks GROUP BY state"
        ).fetchall()
        summary = {str(r["state"]): int(r["n"]) for r in rows}
        summary["recovered_leases"] = recovered
        self.audit.append(actor="sovereign-engine", action="runtime_resume", payload=summary)
        return summary
