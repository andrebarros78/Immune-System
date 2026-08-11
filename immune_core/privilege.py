from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

from .audit import AuditLedger
from .identity import IdentityAuthority, IdentityError
from .storage import SQLiteStateStore


class PrivilegeError(RuntimeError):
    pass


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))


@dataclass(frozen=True)
class PrivilegeGrant:
    token: str
    grant_id: str
    mission_id: str
    task_id: str
    worker_id: str
    action: str
    checkpoint_id: str
    expires_at: int


class PrivilegeAuthority:
    """One-use, short-lived grants. It authorizes; it never bypasses OS privilege controls."""

    MAX_TTL_SECONDS = 300

    def __init__(self, secret: bytes, identities: IdentityAuthority, store: SQLiteStateStore, audit: AuditLedger, issuer: str = "immune-privilege"):
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
            raise ValueError("privilege secret must contain at least 32 bytes")
        self._secret = bytes(secret)
        self.identities = identities
        self.store = store
        self.audit = audit
        self.issuer = issuer
        self.store.conn.execute("CREATE TABLE IF NOT EXISTS used_privilege_grants (grant_id TEXT PRIMARY KEY, used_at REAL NOT NULL)")

    def issue(self, authorizer_token: str, *, mission_id: str, task_id: str, worker_id: str, action: str, checkpoint_id: str, ttl_seconds: int = 120, now: int | None = None) -> PrivilegeGrant:
        if not all(str(v).strip() for v in (mission_id, task_id, worker_id, action, checkpoint_id)):
            raise PrivilegeError("privilege grant requires exact mission, task, worker, action and checkpoint")
        if ttl_seconds <= 0 or ttl_seconds > self.MAX_TTL_SECONDS:
            raise PrivilegeError("privilege grant ttl outside sovereign limit")
        try:
            authorizer = self.identities.verify(authorizer_token, required_scope="grant:privileged", now=now)
        except IdentityError as exc:
            raise PrivilegeError(f"invalid privilege authorizer: {exc}") from exc
        issued = int(time.time() if now is None else now)
        grant_id = secrets.token_hex(16)
        payload = {"iss": self.issuer, "jti": grant_id, "sub": authorizer.subject, "mission_id": mission_id, "task_id": task_id, "worker_id": worker_id, "action": action, "checkpoint_id": checkpoint_id, "iat": issued, "exp": issued + int(ttl_seconds)}
        body = _b64u(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        sig = _b64u(hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest())
        token = f"{body}.{sig}"
        self.audit.append(actor=authorizer.subject, action="privilege_grant_issued", mission_id=mission_id, payload={"grant_id": grant_id, "task_id": task_id, "worker_id": worker_id, "action": action, "checkpoint_id": checkpoint_id, "expires_at": payload["exp"]})
        return PrivilegeGrant(token, grant_id, mission_id, task_id, worker_id, action, checkpoint_id, int(payload["exp"]))

    def consume(self, grant_token: str, *, mission_id: str, task_id: str, worker_id: str, action: str, checkpoint_id: str, now: int | None = None) -> str:
        try:
            body, provided_sig = grant_token.split(".", 1)
            expected = hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest()
            actual = _unb64u(provided_sig)
            if not hmac.compare_digest(expected, actual):
                raise PrivilegeError("invalid privilege signature")
            payload = json.loads(_unb64u(body).decode("utf-8"))
        except PrivilegeError:
            raise
        except Exception as exc:
            raise PrivilegeError("malformed privilege grant") from exc
        current = int(time.time() if now is None else now)
        if payload.get("iss") != self.issuer:
            raise PrivilegeError("invalid privilege issuer")
        if current >= int(payload.get("exp", 0)):
            raise PrivilegeError("privilege grant expired")
        expected_claims = {"mission_id": mission_id, "task_id": task_id, "worker_id": worker_id, "action": action, "checkpoint_id": checkpoint_id}
        for key, value in expected_claims.items():
            if payload.get(key) != value:
                raise PrivilegeError(f"privilege grant target mismatch: {key}")
        grant_id = str(payload.get("jti", ""))
        if not grant_id:
            raise PrivilegeError("missing privilege grant id")
        conn = self.store.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            exists = conn.execute("SELECT 1 FROM used_privilege_grants WHERE grant_id=?", (grant_id,)).fetchone()
            if exists:
                raise PrivilegeError("privilege grant already consumed")
            conn.execute("INSERT INTO used_privilege_grants(grant_id, used_at) VALUES(?,?)", (grant_id, float(current)))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        self.audit.append(actor=worker_id, action="privilege_grant_consumed", mission_id=mission_id, payload={"grant_id": grant_id, "task_id": task_id, "action": action, "checkpoint_id": checkpoint_id})
        return grant_id
