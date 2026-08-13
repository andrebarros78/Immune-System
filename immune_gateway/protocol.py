from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from .contracts import GatewayProtocolError

_ALLOWED_INGRESS_FIELDS = {"kind", "subject", "severity", "attributes", "ts"}
_ALLOWED_SEVERITIES = {"debug", "info", "warning", "error", "critical"}


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def external_signature(secret: bytes, system_id: str, timestamp: int, nonce: str, body: bytes) -> str:
    material = f"{system_id}\n{int(timestamp)}\n{nonce}\n{body_digest(body)}".encode("utf-8")
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def validate_json_shape(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [0]
    if depth > 8:
        raise GatewayProtocolError("external payload exceeds maximum nesting")
    budget[0] += 1
    if budget[0] > 2048:
        raise GatewayProtocolError("external payload exceeds structural budget")
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, str) and len(value) > 16384:
            raise GatewayProtocolError("external string exceeds sovereign bound")
        return
    if isinstance(value, list):
        if len(value) > 256:
            raise GatewayProtocolError("external list exceeds sovereign bound")
        for item in value:
            validate_json_shape(item, depth=depth + 1, budget=budget)
        return
    if isinstance(value, dict):
        if len(value) > 256:
            raise GatewayProtocolError("external object exceeds sovereign bound")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 256:
                raise GatewayProtocolError("external object key is invalid")
            validate_json_shape(item, depth=depth + 1, budget=budget)
        return
    raise GatewayProtocolError("external payload contains unsupported value")


def decode_observation(system_id: str, body: bytes):
    from .contracts import GatewayObservation
    try:
        raw = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayProtocolError("gateway ingress requires UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise GatewayProtocolError("gateway ingress must be an object")
    unknown = set(raw) - _ALLOWED_INGRESS_FIELDS
    if unknown:
        raise GatewayProtocolError(f"external control/unknown fields rejected: {sorted(unknown)}")
    kind = str(raw.get("kind", "")).strip()
    subject = str(raw.get("subject", "")).strip()
    severity = str(raw.get("severity", "info")).lower().strip()
    attrs = raw.get("attributes", {})
    if not kind or not subject or len(kind) > 160 or len(subject) > 256:
        raise GatewayProtocolError("gateway observation kind/subject is invalid")
    if severity not in _ALLOWED_SEVERITIES:
        raise GatewayProtocolError("gateway observation severity is invalid")
    if not isinstance(attrs, dict):
        raise GatewayProtocolError("gateway observation attributes must be an object")
    validate_json_shape(attrs)
    ts = raw.get("ts")
    if ts is not None:
        try:
            ts = float(ts)
        except (TypeError, ValueError) as exc:
            raise GatewayProtocolError("gateway observation ts must be numeric") from exc
    return GatewayObservation(system_id, kind, subject, severity, dict(attrs), ts)
