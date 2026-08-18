from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from immune_core.audit import AuditLedger
from immune_core.identity import IdentityAuthority
from immune_core.providers import ProviderManager
from .http_provider import OpenAICompatibleHTTPProvider


class ProviderConfigurationError(ValueError):
    pass


FORBIDDEN_INLINE_SECRET_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "password",
    "secret",
    "token",
}

RESERVED_REQUEST_FIELDS = {
    "model",
    "messages",
    "max_tokens",
    "tools",
    "tool_choice",
    "authorization",
    "api_key",
}


@dataclass(frozen=True)
class ProviderProfile:
    id: str
    adapter: str
    endpoint: str
    model: str
    api_key_env: str | None
    locality: str = "external"
    cost_per_call: float = 0.0
    priority: int = 0
    enabled: bool = True
    request_options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderRuntimeConfig:
    owner_scope: str
    selection: str
    providers: tuple[ProviderProfile, ...]
    source_path: str

    @staticmethod
    def _check_no_inline_secrets(value: Any, path: str = "root") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).strip().lower()
                if normalized in FORBIDDEN_INLINE_SECRET_KEYS:
                    raise ProviderConfigurationError(
                        f"inline secret field is forbidden at {path}.{key}; use api_key_env"
                    )
                ProviderRuntimeConfig._check_no_inline_secrets(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                ProviderRuntimeConfig._check_no_inline_secrets(child, f"{path}[{index}]")

    @classmethod
    def load(cls, path: str | Path) -> "ProviderRuntimeConfig":
        source = Path(path).resolve()
        try:
            raw = json.loads(source.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderConfigurationError(f"provider configuration unavailable: {source}") from exc
        if not isinstance(raw, dict):
            raise ProviderConfigurationError("provider configuration must be an object")
        cls._check_no_inline_secrets({k: v for k, v in raw.items() if k != "providers"})
        if raw.get("schema") != 1:
            raise ProviderConfigurationError("unsupported provider configuration schema")
        owner_scope = str(raw.get("owner_scope", "")).strip()
        if owner_scope != "immune-provider-proxy":
            raise ProviderConfigurationError("provider owner_scope must be immune-provider-proxy")
        selection = str(raw.get("selection", "priority")).strip().lower()
        if selection != "priority":
            raise ProviderConfigurationError("only priority selection is supported")
        provider_items = raw.get("providers")
        if not isinstance(provider_items, list):
            raise ProviderConfigurationError("providers must be a list")

        profiles: list[ProviderProfile] = []
        seen: set[str] = set()
        for index, item in enumerate(provider_items):
            if not isinstance(item, dict):
                raise ProviderConfigurationError(f"provider {index} must be an object")
            # Inline credentials are never accepted. The only credential field is the ENVIRONMENT VARIABLE NAME.
            for key in item:
                if str(key).strip().lower() in FORBIDDEN_INLINE_SECRET_KEYS:
                    raise ProviderConfigurationError(
                        f"provider {index} contains inline secret field {key}; use api_key_env"
                    )
            provider_id = str(item.get("id", "")).strip()
            adapter = str(item.get("adapter", "")).strip().lower()
            endpoint = str(item.get("endpoint", "")).strip()
            model = str(item.get("model", "")).strip()
            api_key_env = item.get("api_key_env")
            api_key_env = str(api_key_env).strip() if api_key_env else None
            locality = str(item.get("locality", "external")).strip().lower()
            enabled = bool(item.get("enabled", True))
            priority = int(item.get("priority", 0))
            cost_per_call = float(item.get("cost_per_call", 0.0))
            request_options = item.get("request_options", {})

            if not provider_id or provider_id in seen:
                raise ProviderConfigurationError("provider ids must be non-empty and unique")
            seen.add(provider_id)
            if adapter != "openai-compatible-http":
                raise ProviderConfigurationError(
                    f"provider {provider_id}: unsupported adapter {adapter!r}"
                )
            if not endpoint.startswith(("https://", "http://")) or not model:
                raise ProviderConfigurationError(
                    f"provider {provider_id}: endpoint and model are required"
                )
            if locality not in {"local", "external"}:
                raise ProviderConfigurationError(
                    f"provider {provider_id}: locality must be local or external"
                )
            if cost_per_call < 0:
                raise ProviderConfigurationError(
                    f"provider {provider_id}: cost_per_call cannot be negative"
                )
            if locality == "external" and not api_key_env:
                raise ProviderConfigurationError(
                    f"provider {provider_id}: external provider requires api_key_env"
                )
            if api_key_env and not api_key_env.startswith("IMMUNE_"):
                raise ProviderConfigurationError(
                    f"provider {provider_id}: credential environment must use IMMUNE_ namespace"
                )
            if not isinstance(request_options, dict):
                raise ProviderConfigurationError(
                    f"provider {provider_id}: request_options must be an object"
                )
            forbidden = RESERVED_REQUEST_FIELDS.intersection(
                str(key).strip().lower() for key in request_options
            )
            if forbidden:
                raise ProviderConfigurationError(
                    f"provider {provider_id}: reserved request options are forbidden: {sorted(forbidden)}"
                )
            cls._check_no_inline_secrets(request_options, f"providers[{index}].request_options")
            profiles.append(
                ProviderProfile(
                    id=provider_id,
                    adapter=adapter,
                    endpoint=endpoint,
                    model=model,
                    api_key_env=api_key_env,
                    locality=locality,
                    cost_per_call=cost_per_call,
                    priority=priority,
                    enabled=enabled,
                    request_options=dict(request_options),
                )
            )

        profiles.sort(key=lambda profile: (-profile.priority, profile.id))
        return cls(owner_scope, selection, tuple(profiles), str(source))

    @classmethod
    def from_environment(cls, default_path: str | Path) -> "ProviderRuntimeConfig":
        selected = os.environ.get("IMMUNE_PROVIDER_CONFIG") or str(default_path)
        return cls.load(selected)

    def enabled_profiles(self) -> tuple[ProviderProfile, ...]:
        return tuple(profile for profile in self.providers if profile.enabled)

    def public_view(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "owner_scope": self.owner_scope,
            "selection": self.selection,
            "source_path": self.source_path,
            "providers": [
                {
                    "id": profile.id,
                    "adapter": profile.adapter,
                    "enabled": profile.enabled,
                    "priority": profile.priority,
                    "locality": profile.locality,
                    "endpoint": profile.endpoint,
                    "model": profile.model,
                    "credential_present": bool(
                        profile.api_key_env and os.environ.get(profile.api_key_env)
                    ),
                    "cost_per_call": profile.cost_per_call,
                }
                for profile in self.providers
            ],
        }

    def build_manager(
        self,
        identity: IdentityAuthority,
        audit: AuditLedger,
    ) -> ProviderManager:
        providers = []
        for profile in self.enabled_profiles():
            providers.append(
                OpenAICompatibleHTTPProvider(
                    profile.id,
                    profile.endpoint,
                    profile.model,
                    locality=profile.locality,
                    cost_per_call=profile.cost_per_call,
                    api_key_env=profile.api_key_env,
                    request_options=profile.request_options,
                    owner_scope=self.owner_scope,
                )
            )
        return ProviderManager(providers, identity, audit, owner_scope="immune-core")
