from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .operations import CommandGateway, OperatorCommandRef, OperationsError


@dataclass(frozen=True)
class Runbook:
    id: str
    description: str
    action: str
    required_parameters: tuple[str, ...] = ()


DEFAULT_RUNBOOKS = {
    "service-recovery": Runbook("service-recovery", "Diagnose and queue service recovery through Core.", "diagnose", ("service",)),
    "sensor-failure": Runbook("sensor-failure", "Diagnose failed sensor without disabling security controls.", "diagnose", ("sensor_id",)),
    "no-ai": Runbook("no-ai", "Continue deterministic degraded operation while AI is unavailable.", "diagnose", ()),
    "rollback": Runbook("rollback", "Queue rollback to a verified checkpoint.", "rollback", ("checkpoint_id",)),
    "mission-blocked": Runbook("mission-blocked", "Diagnose a blocked mission and gather the concrete blocker.", "diagnose", ()),
    "restore": Runbook("restore", "Queue restoration from a verified checkpoint or backup reference.", "restore", ("checkpoint_id",)),
    "degraded-operation": Runbook("degraded-operation", "Diagnose degraded operation while preserving containment.", "diagnose", ()),
}


class RunbookRunner:
    """Executable means submitted to sovereign Core; runbooks never execute host commands directly."""

    def __init__(self, gateway: CommandGateway, runbooks: dict[str, Runbook] | None = None):
        self.gateway = gateway
        self.runbooks = dict(runbooks or DEFAULT_RUNBOOKS)

    def execute(self, runbook_id: str, *, mission_id: str, operator_token: str, parameters: dict[str, Any] | None = None, now: int | None = None) -> OperatorCommandRef:
        rb = self.runbooks.get(runbook_id)
        if rb is None:
            raise OperationsError("unknown runbook")
        params = dict(parameters or {})
        missing = [name for name in rb.required_parameters if not str(params.get(name, "")).strip()]
        if missing:
            raise OperationsError(f"runbook missing parameters: {', '.join(missing)}")
        return self.gateway.submit(
            mission_id=mission_id,
            action=rb.action,
            operator_token=operator_token,
            target=runbook_id,
            parameters={"runbook": runbook_id, **params},
            now=now,
        )
