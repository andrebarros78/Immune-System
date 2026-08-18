from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class GatewayError(RuntimeError):
    pass


class GatewayAuthenticationError(GatewayError):
    pass


class GatewayAuthorizationError(GatewayError):
    pass


class GatewayProtocolError(GatewayError):
    pass


class GatewayReplayError(GatewayAuthenticationError):
    pass


class GatewayAdapterError(GatewayError):
    pass


@dataclass(frozen=True)
class GatewayObservation:
    system_id: str
    kind: str
    subject: str
    severity: str = "info"
    attributes: dict[str, Any] = field(default_factory=dict)
    ts: float | None = None


@dataclass(frozen=True)
class IngressReceipt:
    system_id: str
    signal_id: str
    evidence_id: str
    accepted_at: float


@dataclass(frozen=True)
class AdapterActionPolicy:
    required_scope: str
    material_change: bool
    irreversible: bool = False
    checkpoint_required: bool = True


@dataclass(frozen=True)
class EgressRequest:
    mission_id: str
    system_id: str
    action: str
    parameters: dict[str, Any] = field(default_factory=dict)
    checkpoint_id: str | None = None


@dataclass(frozen=True)
class EgressReceipt:
    mission_id: str
    system_id: str
    adapter_id: str
    action: str
    ok: bool
    external_reference: str | None
    evidence_id: str
    detail: str = ""


class ProtectedSystemAdapter(Protocol):
    adapter_id: str
    system_id: str

    def collect(self, *, timeout_seconds: float = 2.0) -> GatewayObservation | None: ...
    def action_policy(self, action: str) -> AdapterActionPolicy: ...
    def verify_checkpoint(self, checkpoint_id: str | None) -> bool: ...
    def recovery_ready(self, checkpoint_id: str | None, action: str) -> bool: ...
    def execute(self, action: str, parameters: dict[str, Any], *, timeout_seconds: float = 10.0) -> dict[str, Any]: ...
