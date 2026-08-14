from __future__ import annotations

import time
from typing import Any

from immune_gateway.contracts import GatewayAdapterError, GatewayObservation

from .sandbox import ClosedDigitalTwin, TwinActuator


class DigitalTwinGatewayAdapter:
    """Lab-only protected-system adapter for the closed Digital Twin.

    It has no network, subprocess or host authority. Every mutation is restricted
    to the in-memory TwinWorld or a snapshot located inside the twin sandbox.
    """

    adapter_id = "digital-twin"

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
            {
                "ok": all_running,
                "virtual": True,
                "service_count": len(services),
                "world_digest": self.twin.world.digest(),
            },
            time.time(),
        )

    def execute(self, action: str, parameters: dict[str, Any], *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        action = str(action).strip()
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
            if not snapshot_name or "/" in snapshot_name or "\\" in snapshot_name or snapshot_name in {".", ".."}:
                raise GatewayAdapterError("bounded snapshot_name is required")
            before = self.twin.world.digest()
            snapshot = self.twin.path("snapshots", snapshot_name)
            if not snapshot.is_file():
                raise GatewayAdapterError("digital twin snapshot not found")
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
