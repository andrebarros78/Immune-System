from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Iterable

from .models import Principal


class IdentityError(ValueError):
    pass


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


class IdentityAuthority:
    """Emite identidades internas curtas e autenticadas por HMAC-SHA256."""

    def __init__(self, secret: bytes, issuer: str = "immune-core"):
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
            raise ValueError("identity secret must contain at least 32 bytes")
        self._secret = bytes(secret)
        self.issuer = issuer

    def issue(
        self,
        subject: str,
        kind: str,
        scopes: Iterable[str],
        *,
        ttl_seconds: int = 300,
        now: int | None = None,
    ) -> str:
        if not subject.strip() or not kind.strip():
            raise ValueError("subject and kind are required")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        issued = int(time.time() if now is None else now)
        payload = {
            "sub": subject,
            "kind": kind,
            "scopes": sorted(set(str(s) for s in scopes)),
            "iss": self.issuer,
            "iat": issued,
            "exp": issued + int(ttl_seconds),
            "jti": secrets.token_hex(16),
        }
        body = _b64u_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        sig = _b64u_encode(hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str, *, required_scope: str | None = None, now: int | None = None) -> Principal:
        try:
            body, provided_sig = token.split(".", 1)
            expected = hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest()
            actual = _b64u_decode(provided_sig)
            if not hmac.compare_digest(expected, actual):
                raise IdentityError("invalid signature")
            payload = json.loads(_b64u_decode(body).decode("utf-8"))
        except IdentityError:
            raise
        except Exception as exc:
            raise IdentityError("malformed identity token") from exc

        current = int(time.time() if now is None else now)
        if payload.get("iss") != self.issuer:
            raise IdentityError("invalid issuer")
        if not isinstance(payload.get("iat"), int) or not isinstance(payload.get("exp"), int):
            raise IdentityError("invalid temporal claims")
        if payload["iat"] > current + 30:
            raise IdentityError("token issued in the future")
        if current >= payload["exp"]:
            raise IdentityError("expired token")
        principal = Principal(
            subject=str(payload.get("sub", "")),
            kind=str(payload.get("kind", "")),
            scopes=tuple(str(x) for x in payload.get("scopes", [])),
            issuer=str(payload["iss"]),
            issued_at=int(payload["iat"]),
            expires_at=int(payload["exp"]),
            token_id=str(payload.get("jti", "")),
        )
        if not principal.subject or not principal.kind or not principal.token_id:
            raise IdentityError("incomplete identity")
        if required_scope and not principal.has_scope(required_scope):
            raise IdentityError("required scope missing")
        return principal
