from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Principal:
    subject: str
    kind: str
    scopes: tuple[str, ...]
    issuer: str
    issued_at: int
    expires_at: int
    token_id: str

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "*" in self.scopes


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason: str
    restrictions: tuple[str, ...] = ()
    policy_version: str = "IMUNE-DNA-001/1.0.0"

    @property
    def permitted(self) -> bool:
        return self.decision in {"PERMITIR", "PERMITIR_COM_RESTRIÇÕES"}


@dataclass(frozen=True)
class TaskLease:
    id: str
    mission_id: str
    kind: str
    payload: dict[str, Any]
    attempts: int
    max_attempts: int
    lease_owner: str
    lease_until: float
