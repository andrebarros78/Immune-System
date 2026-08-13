from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .contracts import GatewayAdapterError, GatewayObservation


class WMCP2GatewayAdapter:
    """WMCP2-specific knowledge lives at the gateway, never in immune_core."""

    adapter_id = "wmcp2-local"
    system_id = "wmcp2"

    def __init__(
        self,
        *,
        wmcp2_url: str = "http://127.0.0.1:8766/.well-known/oauth-protected-resource",
        tunnel_core_heartbeat: str | Path = r"C:\Projetos\WINDOWS-MCP\.wmcp2\tunel-core\state\supervisor-heartbeat.json",
        gateway_host: str = "127.0.0.1",
        gateway_port: int = 4010,
        legacy_host: str = "127.0.0.1",
        legacy_port: int = 8765,
    ) -> None:
        self.wmcp2_url = str(wmcp2_url)
        self.tunnel_core_heartbeat = Path(tunnel_core_heartbeat)
        self.gateway_host = str(gateway_host)
        self.gateway_port = int(gateway_port)
        self.legacy_host = str(legacy_host)
        self.legacy_port = int(legacy_port)

    @staticmethod
    def _port_open(host: str, port: int, timeout: float) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _http_ok(self, timeout: float) -> bool:
        request = urllib.request.Request(self.wmcp2_url, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read(64 * 1024).decode("utf-8"))
                return bool(response.status == 200 and isinstance(payload, dict))
        except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError):
            return False

    def _tunnel_state(self, now: float) -> tuple[str, float | None]:
        try:
            payload = json.loads(self.tunnel_core_heartbeat.read_text(encoding="utf-8-sig"))
            at = float(payload.get("at"))
            return str(payload.get("state", "unknown")), max(0.0, now - at)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return "unavailable", None

    def collect(self, *, timeout_seconds: float = 2.0) -> GatewayObservation:
        now = time.time()
        timeout = max(0.05, float(timeout_seconds))
        http_ok = self._http_ok(timeout)
        tunnel_state, heartbeat_age = self._tunnel_state(now)
        adapter_gateway_ok = self._port_open(self.gateway_host, self.gateway_port, timeout)
        legacy_ok = self._port_open(self.legacy_host, self.legacy_port, timeout)
        tunnel_ok = tunnel_state == "healthy" and heartbeat_age is not None and heartbeat_age <= 30.0
        ok = bool(http_ok and tunnel_ok and adapter_gateway_ok)
        return GatewayObservation(
            self.system_id,
            "wmcp2.health",
            "wmcp2",
            "info" if ok else "error",
            {
                "ok": ok,
                "wmcp2_http_ok": http_ok,
                "tunnel_core_state": tunnel_state,
                "tunnel_core_heartbeat_age_seconds": heartbeat_age,
                "wmcp2_gateway_port_open": adapter_gateway_ok,
                "legacy_port_open": legacy_ok,
            },
            now,
        )

    def execute(self, action: str, parameters: dict[str, Any], *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        raise GatewayAdapterError("WMCP2 mutation adapter is not configured; no direct core fallback is allowed")


class HTTPJSONGatewayAdapter:
    """Generic REST adapter. Protocol differences are absorbed here, outside immune_core."""

    def __init__(
        self,
        system_id: str,
        adapter_id: str,
        *,
        action_endpoint: str,
        credential_env: str | None = None,
        health_endpoint: str | None = None,
    ) -> None:
        if not system_id.strip() or not adapter_id.strip():
            raise ValueError("system_id and adapter_id are required")
        if not action_endpoint.startswith(("http://", "https://")):
            raise ValueError("action endpoint must be http(s)")
        if credential_env and not credential_env.startswith("IMMUNE_GATEWAY_"):
            raise ValueError("gateway adapter credentials must use IMMUNE_GATEWAY_ namespace")
        self.system_id = system_id.strip()
        self.adapter_id = adapter_id.strip()
        self.action_endpoint = action_endpoint
        self.credential_env = credential_env
        self.health_endpoint = health_endpoint

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.credential_env:
            secret = os.environ.get(self.credential_env, "")
            if not secret:
                raise GatewayAdapterError(f"missing gateway adapter credential environment: {self.credential_env}")
            headers["Authorization"] = f"Bearer {secret}"
        return headers

    def collect(self, *, timeout_seconds: float = 2.0) -> GatewayObservation | None:
        if not self.health_endpoint:
            return None
        request = urllib.request.Request(self.health_endpoint, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=float(timeout_seconds)) as response:
                raw = response.read(256 * 1024)
                payload = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            return GatewayObservation(self.system_id, "adapter.health", self.system_id, "error", {"ok": False, "error": type(exc).__name__}, time.time())
        return GatewayObservation(self.system_id, "adapter.health", self.system_id, "info", {"ok": True, "payload": payload}, time.time())

    def execute(self, action: str, parameters: dict[str, Any], *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        if not action.strip() or len(action) > 160:
            raise GatewayAdapterError("gateway action is invalid")
        body = json.dumps({"action": action, "parameters": parameters}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.action_endpoint, data=body, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=float(timeout_seconds)) as response:
                raw = response.read(256 * 1024)
                payload = json.loads(raw.decode("utf-8")) if raw else {}
                if not isinstance(payload, dict):
                    raise GatewayAdapterError("protected system returned non-object response")
                payload.setdefault("ok", 200 <= response.status < 300)
                return payload
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError) as exc:
            raise GatewayAdapterError(f"protected-system adapter failed: {type(exc).__name__}") from exc


class TCPHealthGatewayAdapter:
    """Gateway-owned TCP availability probe for one explicitly configured protected endpoint."""

    def __init__(self, system_id: str, host: str, port: int, *, adapter_id: str = "tcp-health") -> None:
        if not system_id.strip() or not host.strip() or not 1 <= int(port) <= 65535:
            raise ValueError("system_id, host and valid port are required")
        self.system_id = system_id.strip()
        self.adapter_id = adapter_id.strip()
        self.host = host.strip()
        self.port = int(port)

    def collect(self, *, timeout_seconds: float = 2.0) -> GatewayObservation:
        started = time.monotonic()
        ok = False
        error = ""
        try:
            with socket.create_connection((self.host, self.port), timeout=float(timeout_seconds)):
                ok = True
        except OSError as exc:
            error = type(exc).__name__
        elapsed_ms = (time.monotonic() - started) * 1000.0
        return GatewayObservation(
            self.system_id,
            "tcp.health",
            f"tcp:{self.host}:{self.port}",
            "info" if ok else "error",
            {"reachable": ok, "error": error, "latency_ms": elapsed_ms},
            time.time(),
        )

    def execute(self, action: str, parameters: dict[str, Any], *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        raise GatewayAdapterError("TCP health adapter is observation-only")
