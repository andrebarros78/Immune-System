from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import GatewayProtocolError


@dataclass(frozen=True)
class SystemBinding:
    system_id: str
    adapter: str
    enabled: bool
    ingress: str
    peer_secret_env: str | None
    config: dict[str, Any]


@dataclass(frozen=True)
class GatewayRuntimeConfig:
    owner_scope: str
    bind_host: str
    bind_port: int
    max_body_bytes: int
    max_clock_skew_seconds: int
    nonce_ttl_seconds: int
    systems: tuple[SystemBinding, ...]
    source_path: str

    @classmethod
    def load(cls, path: str | Path) -> "GatewayRuntimeConfig":
        source = Path(path).resolve()
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GatewayProtocolError("gateway runtime configuration unavailable") from exc
        if raw.get("schema") != 1 or raw.get("owner_scope") != "immune-gateway":
            raise GatewayProtocolError("gateway configuration must be schema 1 and owner_scope immune-gateway")
        if any(k in raw for k in ("secret", "api_key", "token", "password")):
            raise GatewayProtocolError("inline gateway secrets are forbidden")
        bind = raw.get("bind", {})
        if not isinstance(bind, dict):
            raise GatewayProtocolError("bind must be an object")
        host = str(bind.get("host", "127.0.0.1"))
        port = int(bind.get("port", 4020))
        if not 1 <= port <= 65535:
            raise GatewayProtocolError("gateway bind port outside valid range")
        limits = raw.get("limits", {})
        if not isinstance(limits, dict):
            raise GatewayProtocolError("limits must be an object")
        max_body = int(limits.get("max_body_bytes", 65536))
        skew = int(limits.get("max_clock_skew_seconds", 60))
        nonce_ttl = int(limits.get("nonce_ttl_seconds", 300))
        if not 1024 <= max_body <= 1048576 or not 5 <= skew <= 300 or not 30 <= nonce_ttl <= 3600:
            raise GatewayProtocolError("gateway limits outside sovereign bounds")
        bindings: list[SystemBinding] = []
        seen: set[str] = set()
        systems = raw.get("systems", [])
        if not isinstance(systems, list):
            raise GatewayProtocolError("systems must be a list")
        for item in systems:
            if not isinstance(item, dict):
                raise GatewayProtocolError("system binding must be an object")
            forbidden = set(item).intersection({"secret", "api_key", "token", "password"})
            if forbidden:
                raise GatewayProtocolError("inline system secrets are forbidden")
            sid = str(item.get("id", "")).strip()
            adapter = str(item.get("adapter", "")).strip()
            ingress = str(item.get("ingress", "push-signed")).strip()
            if not sid or sid in seen or not adapter:
                raise GatewayProtocolError("system id/adapter missing or duplicated")
            if ingress not in {"push-signed", "pull", "disabled"}:
                raise GatewayProtocolError("unsupported ingress mode")
            secret_env = item.get("peer_secret_env")
            if secret_env is not None:
                secret_env = str(secret_env).strip()
                if not secret_env.startswith("IMMUNE_GATEWAY_"):
                    raise GatewayProtocolError("peer secret env must use IMMUNE_GATEWAY_ namespace")
            if ingress == "push-signed" and not secret_env:
                raise GatewayProtocolError("push-signed system requires peer_secret_env")
            binding_config = item.get("config", {})
            if not isinstance(binding_config, dict):
                raise GatewayProtocolError("system config must be an object")
            bindings.append(SystemBinding(sid, adapter, bool(item.get("enabled", True)), ingress, secret_env, dict(binding_config)))
            seen.add(sid)
        return cls("immune-gateway", host, port, max_body, skew, nonce_ttl, tuple(bindings), str(source))

    def binding(self, system_id: str) -> SystemBinding:
        for item in self.systems:
            if item.system_id == system_id and item.enabled:
                return item
        raise GatewayProtocolError("system is not registered/enabled at gateway")

    def peer_secret(self, system_id: str) -> bytes:
        binding = self.binding(system_id)
        if binding.ingress != "push-signed" or not binding.peer_secret_env:
            raise GatewayProtocolError("system does not use signed push ingress")
        value = os.environ.get(binding.peer_secret_env, "")
        if len(value.encode("utf-8")) < 32:
            raise GatewayProtocolError(f"missing/weak peer secret environment: {binding.peer_secret_env}")
        return value.encode("utf-8")

    def public_status(self) -> dict[str, Any]:
        return {
            "owner_scope": self.owner_scope,
            "bind": {"host": self.bind_host, "port": self.bind_port},
            "systems": [
                {
                    "id": item.system_id,
                    "adapter": item.adapter,
                    "enabled": item.enabled,
                    "ingress": item.ingress,
                    "credential_present": bool(item.peer_secret_env and os.environ.get(item.peer_secret_env)),
                }
                for item in self.systems
            ],
            "source_path": self.source_path,
        }
