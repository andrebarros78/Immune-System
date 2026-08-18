from __future__ import annotations

import time
from typing import Any

from immune_gateway.contracts import AdapterActionPolicy, GatewayAdapterError, GatewayObservation

from .sandbox import ClosedDigitalTwin, TwinActuator


class DigitalTwinGatewayAdapter:
    """Lab-only adapter. Risk metadata and checkpoint verification are adapter-owned."""

    adapter_id = "digital-twin"
    _POLICIES = {
        "set_config": AdapterActionPolicy("gateway:egress", material_change=True, checkpoint_required=True),
        "restart_service": AdapterActionPolicy("gateway:egress", material_change=True, checkpoint_required=True),
        "restore_snapshot": AdapterActionPolicy("gateway:egress", material_change=True, checkpoint_required=True),
    }

    def __init__(self, twin: ClosedDigitalTwin, *, system_id: str = "twin-system") -> None:
        if not system_id.strip():
            raise ValueError("system_id is required")
        self.twin = twin
        self.system_id = system_id.strip()
        self._actuator = TwinActuator(twin.world)

    def collect(self, *, timeout_seconds: float = 2.0) -> GatewayObservation:
        services = self.twin.world.services
        all_running = all(service.running for service in services.values()) if services else True
        return GatewayObservation(
            self.system_id,
            "digital_twin.health",
            self.system_id,
            "info" if all_running else "error",
            {"ok": all_running, "virtual": True, "service_count": len(services), "world_digest": self.twin.world.digest()},
            time.time(),
        )

    def action_policy(self, action: str) -> AdapterActionPolicy:
        try:
            return self._POLICIES[str(action).strip()]
        except KeyError as exc:
            raise GatewayAdapterError("unregistered digital twin action") from exc

    def verify_checkpoint(self, checkpoint_id: str | None) -> bool:
        if not checkpoint_id or "/" in checkpoint_id or "\\" in checkpoint_id or checkpoint_id in {".", ".."}:
            return False
        return self.twin.path("snapshots", checkpoint_id).is_file()

    def recovery_ready(self, checkpoint_id: str | None, action: str) -> bool:
        return self.verify_checkpoint(checkpoint_id)

    def execute(self, action: str, parameters: dict[str, Any], *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        action = str(action).strip()
        self.action_policy(action)
        if timeout_seconds <= 0:
            raise GatewayAdapterError("digital twin timeout must be positive")
        if action in {"set_config", "restart_service"}:
            result = self._actuator.apply(action, dict(parameters))
            return {
                "ok": True,
                "external_reference": result["after"],
                "detail": f"digital_twin:{action}:changed={bool(result['changed'])}",
                "before": result["before"],
                "after": result["after"],
            }
        if action == "restore_snapshot":
            snapshot_name = str(parameters.get("snapshot_name") or "").strip()
            if not self.verify_checkpoint(snapshot_name):
                raise GatewayAdapterError("bounded existing snapshot_name is required")
            before = self.twin.world.digest()
            snapshot = self.twin.path("snapshots", snapshot_name)
            self.twin.restore_snapshot(snapshot)
            after = self.twin.world.digest()
            return {
                "ok": True,
                "external_reference": after,
                "detail": f"digital_twin:restore_snapshot:changed={before != after}",
                "before": before,
                "after": after,
            }
        raise GatewayAdapterError(f"unsupported digital twin gateway action: {action}")
