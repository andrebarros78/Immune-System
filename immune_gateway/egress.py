from __future__ import annotations

import time
from typing import Mapping

from immune_core.audit import AuditLedger
from immune_core.identity import IdentityAuthority, IdentityError
from immune_core.observability import ObservabilityStore
from immune_core.storage import SQLiteStateStore
from immune_fortress.capability import ActionCapabilityAuthority, CapabilityError

from .contracts import EgressReceipt, EgressRequest, GatewayAuthorizationError, GatewayProtocolError, ProtectedSystemAdapter
from .runtime_config import GatewayRuntimeConfig


_ACTIVE_MISSION_STATES = {"AUTHORIZED", "DISCOVERING", "RUNNING", "DEGRADED", "VALIDATING"}


class GatewayEgress:
    """Capability-gated egress. Caller-provided authorization booleans do not exist."""

    def __init__(
        self,
        store: SQLiteStateStore,
        identity: IdentityAuthority,
        capabilities: ActionCapabilityAuthority,
        audit: AuditLedger,
        config: GatewayRuntimeConfig,
        adapters: Mapping[str, ProtectedSystemAdapter],
    ) -> None:
        self.store = store
        self.identity = identity
        self.capabilities = capabilities
        self.audit = audit
        self.config = config
        self.adapters = dict(adapters)
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
        capability_token: str,
        timeout_seconds: float = 10.0,
        now: int | None = None,
    ) -> EgressReceipt:
        try:
            principal = self.identity.verify(internal_token, required_scope="gateway:egress", now=now)
        except IdentityError as exc:
            raise GatewayAuthorizationError(f"invalid internal gateway identity: {exc}") from exc
        mission = self.store.get_mission(request.mission_id)
        if mission is None or str(mission["state"]) not in _ACTIVE_MISSION_STATES:
            raise GatewayAuthorizationError("egress mission is not active")
        if str(mission["system_id"]) != request.system_id:
            raise GatewayAuthorizationError("egress target differs from mission protected system")
        binding = self.config.binding(request.system_id)
        adapter = self.adapters.get(request.system_id)
        if adapter is None or adapter.system_id != request.system_id or adapter.adapter_id != binding.adapter:
            raise GatewayProtocolError("protected-system adapter unavailable or mismatched")
        try:
            action_policy = adapter.action_policy(request.action)
        except Exception as exc:
            raise GatewayAuthorizationError("adapter action is not registered") from exc
        if not action_policy.required_scope:
            raise GatewayAuthorizationError("adapter action lacks required scope")
        checkpoint_valid = adapter.verify_checkpoint(request.checkpoint_id)
        if (action_policy.checkpoint_required or action_policy.material_change) and not checkpoint_valid:
            raise GatewayAuthorizationError("adapter checkpoint verification failed")
        if action_policy.irreversible and not adapter.recovery_ready(request.checkpoint_id, request.action):
            raise GatewayAuthorizationError("adapter recovery verification failed")
        try:
            capability_id = self.capabilities.consume(
                capability_token,
                mission_id=request.mission_id,
                system_id=request.system_id,
                action=request.action,
                parameters=dict(request.parameters),
                checkpoint_id=request.checkpoint_id,
                now=now,
            )
        except CapabilityError as exc:
            raise GatewayAuthorizationError(f"invalid action capability: {exc}") from exc
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
                "capability_id": capability_id,
                "checkpoint_id": request.checkpoint_id,
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
                "capability_id": capability_id,
            },
            now=started,
        )
        return EgressReceipt(request.mission_id, request.system_id, adapter.adapter_id, request.action, ok, external_reference, evidence.id, detail)
