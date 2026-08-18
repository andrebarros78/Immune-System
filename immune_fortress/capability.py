from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from immune_core.identity import IdentityAuthority, IdentityError
from immune_core.storage import SQLiteStateStore


class CapabilityError(RuntimeError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def parameter_digest(parameters: dict[str, Any]) -> str:
    raw = json.dumps(parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ActionCapability:
    token: str
    capability_id: str
    mission_id: str
    system_id: str
    action: str
    checkpoint_id: str | None
    expires_at: int


class ActionCapabilityAuthority:
    """One-use exact-action capabilities with a key independent from identity keys."""

    MAX_TTL_SECONDS = 90

    def __init__(self, secret: bytes, identities: IdentityAuthority, store: SQLiteStateStore, issuer: str = "immune-capability"):
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
            raise ValueError("capability secret must contain at least 32 bytes")
        self._secret = bytes(secret)
        self.identities = identities
        self.store = store
        self.issuer = issuer
        self.store.conn.execute(
            "CREATE TABLE IF NOT EXISTS used_action_capabilities (capability_id TEXT PRIMARY KEY, used_at REAL NOT NULL)"
        )

    def issue(self, authorizer_token: str, *, mission_id: str, system_id: str, action: str, parameters: dict[str, Any], checkpoint_id: str | None, ttl_seconds: int = 45, now: int | None = None) -> ActionCapability:
        try:
            principal = self.identities.verify(authorizer_token, required_scope="capability:issue", now=now)
        except IdentityError as exc:
            raise CapabilityError(f"invalid capability authorizer: {exc}") from exc
        if not all(str(v).strip() for v in (mission_id, system_id, action)):
            raise CapabilityError("capability requires mission, system and action")
        if ttl_seconds <= 0 or ttl_seconds > self.MAX_TTL_SECONDS:
            raise CapabilityError("capability ttl outside sovereign limit")
        issued = int(time.time() if now is None else now)
        cid = secrets.token_hex(16)
        payload = {
            "iss": self.issuer,
            "jti": cid,
            "sub": principal.subject,
            "mission_id": mission_id,
            "system_id": system_id,
            "action": action,
            "parameters_sha256": parameter_digest(parameters),
            "checkpoint_id": checkpoint_id,
            "iat": issued,
            "exp": issued + int(ttl_seconds),
        }
        body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        sig = _b64(hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest())
        return ActionCapability(f"{body}.{sig}", cid, mission_id, system_id, action, checkpoint_id, int(payload["exp"]))

    def consume(self, token: str, *, mission_id: str, system_id: str, action: str, parameters: dict[str, Any], checkpoint_id: str | None, now: int | None = None) -> str:
        try:
            body, provided = token.split(".", 1)
            expected = hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest()
            actual = _unb64(provided)
            if not hmac.compare_digest(expected, actual):
                raise CapabilityError("invalid capability signature")
            payload = json.loads(_unb64(body).decode("utf-8"))
        except CapabilityError:
            raise
        except Exception as exc:
            raise CapabilityError("malformed capability") from exc
        current = int(time.time() if now is None else now)
        if payload.get("iss") != self.issuer or current >= int(payload.get("exp", 0)):
            raise CapabilityError("capability expired or wrong issuer")
        expected_claims = {
            "mission_id": mission_id,
            "system_id": system_id,
            "action": action,
            "parameters_sha256": parameter_digest(parameters),
            "checkpoint_id": checkpoint_id,
        }
        for key, value in expected_claims.items():
            if payload.get(key) != value:
                raise CapabilityError(f"capability target mismatch: {key}")
        cid = str(payload.get("jti", ""))
        if not cid:
            raise CapabilityError("capability id missing")
        conn = self.store.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            if conn.execute("SELECT 1 FROM used_action_capabilities WHERE capability_id=?", (cid,)).fetchone():
                raise CapabilityError("capability already consumed")
            conn.execute("INSERT INTO used_action_capabilities(capability_id,used_at) VALUES(?,?)", (cid, float(current)))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return cid
