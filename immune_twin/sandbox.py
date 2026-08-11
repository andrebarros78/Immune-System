from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import socket
import subprocess
import tempfile
import urllib.request
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


class SandboxViolation(RuntimeError):
    pass


@dataclass
class VirtualClock:
    now: float = 2_100_000_000.0

    def tick(self, seconds: float = 1.0) -> float:
        self.now += float(seconds)
        return self.now


@dataclass
class TwinService:
    name: str
    running: bool = True
    config: dict[str, Any] = field(default_factory=dict)
    dependencies: tuple[str, ...] = ()


@dataclass
class TwinWorld:
    clock: VirtualClock = field(default_factory=VirtualClock)
    services: dict[str, TwinService] = field(default_factory=dict)
    ai_available: bool = True
    release_version: str = "1.0.0"
    human_gate_open: bool = False
    events: list[dict[str, Any]] = field(default_factory=list)

    def add_service(self, name: str, *, running: bool = True, config: dict[str, Any] | None = None, dependencies: Iterable[str] = ()) -> None:
        self.services[name] = TwinService(name, running, dict(config or {}), tuple(dependencies))

    def fail_service(self, name: str, reason: str = "simulated_failure") -> None:
        service = self.services[name]
        service.running = False
        self.events.append({"ts": self.clock.tick(), "kind": "failure", "service": name, "reason": reason})

    def restart_service(self, name: str) -> None:
        self.services[name].running = True
        self.events.append({"ts": self.clock.tick(), "kind": "restart", "service": name})

    def set_config(self, name: str, key: str, value: Any) -> None:
        self.services[name].config[key] = value
        self.events.append({"ts": self.clock.tick(), "kind": "config", "service": name, "key": key, "value": value})

    def snapshot(self) -> dict[str, Any]:
        return {
            "clock": self.clock.now,
            "ai_available": self.ai_available,
            "release_version": self.release_version,
            "human_gate_open": self.human_gate_open,
            "services": {
                name: {
                    "running": svc.running,
                    "config": dict(sorted(svc.config.items())),
                    "dependencies": list(svc.dependencies),
                }
                for name, svc in sorted(self.services.items())
            },
        }

    def digest(self) -> str:
        raw = json.dumps(self.snapshot(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class ExternalEffectGuard(AbstractContextManager["ExternalEffectGuard"]):
    """Fail-closed guard. The temporary sandbox is the only writable surface."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.violations: list[str] = []
        self._patches: list[tuple[Any, str, Any]] = []

    def _patch(self, obj: Any, name: str, replacement: Any) -> None:
        self._patches.append((obj, name, getattr(obj, name)))
        setattr(obj, name, replacement)

    def _violate(self, message: str):
        self.violations.append(message)
        raise SandboxViolation(message)

    def __enter__(self) -> "ExternalEffectGuard":
        guard = self

        def blocked_create_connection(address, *args, **kwargs):
            return guard._violate(f"network:{address}")

        def blocked_connect(sock, address):
            return guard._violate(f"network:{address}")

        def blocked_urlopen(*args, **kwargs):
            return guard._violate("urllib")

        def blocked_run(*args, **kwargs):
            return guard._violate("subprocess.run")

        def blocked_popen(*args, **kwargs):
            return guard._violate("subprocess.Popen")

        def blocked_system(*args, **kwargs):
            return guard._violate("os.system")

        original_open = builtins.open

        def guarded_open(file, mode="r", *args, **kwargs):
            if any(flag in str(mode) for flag in ("w", "a", "x", "+")):
                path = Path(file).expanduser().resolve()
                if path != self.root and self.root not in path.parents:
                    return guard._violate(f"write_outside:{path}")
            return original_open(file, mode, *args, **kwargs)

        self._patch(socket, "create_connection", blocked_create_connection)
        self._patch(socket.socket, "connect", blocked_connect)
        self._patch(urllib.request, "urlopen", blocked_urlopen)
        self._patch(subprocess, "run", blocked_run)
        self._patch(subprocess, "Popen", blocked_popen)
        self._patch(os, "system", blocked_system)
        self._patch(builtins, "open", guarded_open)
        self._patch(io, "open", guarded_open)
        return self

    def __exit__(self, exc_type, exc, tb):
        for obj, name, original in reversed(self._patches):
            setattr(obj, name, original)
        self._patches.clear()
        return False

    @property
    def clean(self) -> bool:
        return not self.violations


class TwinSensor:
    def __init__(self, world: TwinWorld, service_name: str):
        self.world = world
        self.service_name = service_name
        self.sensor_id = f"twin-service:{service_name}"

    def collect(self):
        service = self.world.services[self.service_name]
        subject = f"service:{self.service_name}"
        yield {
            "type": "resource",
            "resource_id": subject,
            "kind": "service",
            "name": self.service_name,
            "attributes": {"virtual": True, "running": service.running, "config": dict(service.config)},
        }
        for dep in service.dependencies:
            yield {
                "type": "dependency",
                "src": subject,
                "dst": f"service:{dep}",
                "relation": "depends_on",
                "attributes": {"virtual": True},
            }
        yield {
            "type": "signal",
            "kind": "health",
            "subject": subject,
            "severity": "info" if service.running else "error",
            "attributes": {
                "status": "up" if service.running else "down",
                "incident_key": subject,
                "virtual": True,
            },
        }


class TwinActuator:
    """Virtual actuator: modifies TwinWorld only. No OS/network/subprocess authority."""

    ALLOWED = {"restart_service", "set_config", "set_ai", "activate_release"}

    def __init__(self, world: TwinWorld):
        self.world = world

    def apply(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        if action not in self.ALLOWED:
            raise SandboxViolation(f"unregistered_virtual_action:{action}")
        before = self.world.digest()
        if action == "restart_service":
            self.world.restart_service(str(params["service"]))
        elif action == "set_config":
            self.world.set_config(str(params["service"]), str(params["key"]), params.get("value"))
        elif action == "set_ai":
            self.world.ai_available = bool(params["available"])
            self.world.events.append({"ts": self.world.clock.tick(), "kind": "ai", "available": self.world.ai_available})
        elif action == "activate_release":
            self.world.release_version = str(params["version"])
            self.world.events.append({"ts": self.world.clock.tick(), "kind": "release", "version": self.world.release_version})
        after = self.world.digest()
        return {"action": action, "before": before, "after": after, "changed": before != after}


class ClosedDigitalTwin(AbstractContextManager["ClosedDigitalTwin"]):
    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="immune-digital-twin-")
        self.root = Path(self._tmp.name).resolve()
        self.world = TwinWorld()
        self.guard = ExternalEffectGuard(self.root)
        self._previous_tempdir: str | None = None

    def __enter__(self) -> "ClosedDigitalTwin":
        local_tmp = self.root / "tmp"
        local_tmp.mkdir(parents=True, exist_ok=True)
        self._previous_tempdir = tempfile.tempdir
        tempfile.tempdir = str(local_tmp)
        self.guard.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            return self.guard.__exit__(exc_type, exc, tb)
        finally:
            tempfile.tempdir = self._previous_tempdir
            self._tmp.cleanup()

    def path(self, *parts: str) -> Path:
        p = self.root.joinpath(*parts).resolve()
        if p != self.root and self.root not in p.parents:
            raise SandboxViolation(f"path_escape:{p}")
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def snapshot_to(self, name: str) -> Path:
        path = self.path("snapshots", name)
        path.write_text(json.dumps(self.world.snapshot(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def restore_snapshot(self, path: str | Path) -> None:
        p = Path(path).resolve()
        if self.root not in p.parents:
            raise SandboxViolation("snapshot_outside_sandbox")
        data = json.loads(p.read_text(encoding="utf-8"))
        self.world.clock.now = float(data["clock"])
        self.world.ai_available = bool(data["ai_available"])
        self.world.release_version = str(data["release_version"])
        self.world.human_gate_open = bool(data["human_gate_open"])
        self.world.services.clear()
        for name, item in data["services"].items():
            self.world.add_service(
                name,
                running=bool(item["running"]),
                config=dict(item["config"]),
                dependencies=tuple(item["dependencies"]),
            )
