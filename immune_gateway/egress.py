from __future__ import annotations

import time

from immune_core.audit import AuditLedger
from immune_core.identity import IdentityAuthority, IdentityError
from immune_core.observability import ObservabilityStore
from immune_core.policy import PolicyGuard
from immune_core.storage import SQLiteStateStore

from .contracts import (
    EgressReceipt,
    EgressRequest,
    GatewayAuthorizationError,
    GatewayProtocolError,
    ProtectedSystemAdapter,
)
from .runtime_config import GatewayRuntimeConfig

_ACTIVE_MISSION_STATES = {"AUTHORIZED", "DISCOVERING", "RUNNING", "DEGRADED", "VALIDATING"}


class GatewayEgress:
    """Internal-only path used by the immune system to act on a protected system."""

    def __init__(
        self,
        store: SQLiteStateStore,
        identity: IdentityAuthority,
        policy: PolicyGuard,
        audit: AuditLedger,
        config: GatewayRuntimeConfig,
        adapters: dict[str, ProtectedSystemAdapter],
    ) -> None:
        self.store = store
        self.identity = identity
        self.policy = policy
        self.audit = audit
        self.config = config
        self.adapters = adapters
        self.observability = ObservabilityStore(store, audit)
        self.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS gateway_egress_receipts(
                evidence_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                system_id TEXT NOT NULL,
                adapter_id TEXT NOT NULL,
                action TEXT NOT NULL,
                ok INTEGER NOT NULL,
                external_reference TEXT,
                detail TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )

    def execute(
        self,
        request: EgressRequest,
        *,
        internal_token: str,
        timeout_seconds: float = 10.0,
        now: int | None = None,
    ) -> EgressReceipt:
        try:
            principal = self.identity.verify(internal_token, required_scope="gateway:egress", now=now)
        except IdentityError as exc:
            raise GatewayAuthorizationError(f"invalid internal gateway identity: {exc}") from exc
        mission = self.store.get_mission(request.mission_id)
        if mission is None:
            raise GatewayAuthorizationError("egress mission not found")
        if str(mission["system_id"]) != request.system_id:
            raise GatewayAuthorizationError("egress target differs from mission protected system")
        binding = self.config.binding(request.system_id)
        adapter = self.adapters.get(request.system_id)
        if adapter is None:
            raise GatewayProtocolError("protected-system adapter unavailable")
        decision = self.policy.evaluate_token(
            internal_token,
            {
                "mission_id": request.mission_id,
                "action": "gateway_protected_system_egress",
                "required_scope": "gateway:egress",
                "mission_authorized": str(mission["state"]) in _ACTIVE_MISSION_STATES,
                "system_authorized": adapter.system_id == request.system_id and adapter.adapter_id == binding.adapter,
                "scope_ok": True,
                "material_change": bool(request.material_change),
                "checkpoint_valid": bool(request.checkpoint_valid),
                "irreversible": bool(request.irreversible),
                "recovery_verified": bool(request.recovery_verified),
            },
            now=now,
        )
        if decision.decision not in {"PERMITIR", "PERMITIR_COM_RESTRIÇÕES"}:
            raise GatewayAuthorizationError(f"{decision.decision}: {decision.reason}")
        started = time.time() if now is None else float(now)
        result = adapter.execute(request.action, dict(request.parameters), timeout_seconds=timeout_seconds)
        if not isinstance(result, dict):
            raise GatewayProtocolError("adapter egress result must be an object")
        ok = bool(result.get("ok", False))
        external_reference = str(result.get("external_reference")) if result.get("external_reference") is not None else None
        detail = str(result.get("detail", ""))[:2048]
        evidence = self.observability.evidence(
            kind="gateway_egress_result",
            mission_id=request.mission_id,
            payload={
                "system_id": request.system_id,
                "adapter_id": adapter.adapter_id,
                "action": request.action,
                "ok": ok,
                "external_reference": external_reference,
                "principal": principal.subject,
            },
            ts=started,
        )
        self.store.conn.execute(
            "INSERT INTO gateway_egress_receipts(evidence_id,mission_id,system_id,adapter_id,action,ok,external_reference,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (evidence.id, request.mission_id, request.system_id, adapter.adapter_id, request.action, int(ok), external_reference, detail, started),
        )
        self.audit.append(
            actor=principal.subject,
            action="gateway_egress_completed",
            mission_id=request.mission_id,
            payload={
                "system_id": request.system_id,
                "adapter_id": adapter.adapter_id,
                "action": request.action,
                "ok": ok,
                "evidence_id": evidence.id,
            },
            now=started,
        )
        return EgressReceipt(
            request.mission_id,
            request.system_id,
            adapter.adapter_id,
            request.action,
            ok,
            external_reference,
            evidence.id,
            detail,
        )
