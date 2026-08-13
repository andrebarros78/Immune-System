from __future__ import annotations

import hmac
import time

from immune_core.audit import AuditLedger
from immune_core.observability import ObservabilityStore, SignalProcessor
from immune_core.storage import SQLiteStateStore

from .contracts import (
    GatewayAuthenticationError,
    GatewayAuthorizationError,
    GatewayProtocolError,
    GatewayReplayError,
    IngressReceipt,
    ProtectedSystemAdapter,
)
from .protocol import decode_observation, external_signature
from .runtime_config import GatewayRuntimeConfig


class GatewayIngress:
    """External side of the gateway. Data may enter; authority may not."""

    def __init__(
        self,
        store: SQLiteStateStore,
        audit: AuditLedger,
        config: GatewayRuntimeConfig,
        adapters: dict[str, ProtectedSystemAdapter],
    ) -> None:
        self.store = store
        self.audit = audit
        self.config = config
        self.adapters = adapters
        self.observability = ObservabilityStore(store, audit)
        self.processor = SignalProcessor(self.observability)
        self.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS gateway_nonces(
                system_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                accepted_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                PRIMARY KEY(system_id, nonce)
            );
            CREATE INDEX IF NOT EXISTS idx_gateway_nonces_expiry
                ON gateway_nonces(expires_at);
            """
        )

    def _claim_nonce(self, system_id: str, nonce: str, *, now: float) -> None:
        if len(nonce) < 16 or len(nonce) > 128 or any(ch.isspace() for ch in nonce):
            raise GatewayAuthenticationError("invalid gateway nonce")
        self.store.conn.execute("DELETE FROM gateway_nonces WHERE expires_at<=?", (now,))
        try:
            self.store.conn.execute(
                "INSERT INTO gateway_nonces(system_id,nonce,accepted_at,expires_at) VALUES(?,?,?,?)",
                (system_id, nonce, now, now + self.config.nonce_ttl_seconds),
            )
        except Exception as exc:
            raise GatewayReplayError("replayed gateway nonce") from exc

    def verify_signature(
        self,
        system_id: str,
        body: bytes,
        *,
        timestamp: int,
        nonce: str,
        signature: str,
        now: float | None = None,
    ) -> None:
        current = time.time() if now is None else float(now)
        binding = self.config.binding(system_id)
        if binding.ingress != "push-signed":
            raise GatewayAuthenticationError("system does not accept external push ingress")
        if abs(current - int(timestamp)) > self.config.max_clock_skew_seconds:
            raise GatewayAuthenticationError("gateway timestamp outside allowed skew")
        if len(body) > self.config.max_body_bytes:
            raise GatewayProtocolError("gateway body exceeds configured limit")
        expected = external_signature(self.config.peer_secret(system_id), system_id, int(timestamp), nonce, body)
        if not hmac.compare_digest(expected, str(signature).lower()):
            raise GatewayAuthenticationError("invalid gateway signature")
        self._claim_nonce(system_id, nonce, now=current)

    def _accept(self, observation, *, source: str, now: float | None = None) -> IngressReceipt:
        binding = self.config.binding(observation.system_id)
        if binding.ingress == "disabled":
            raise GatewayAuthorizationError("gateway ingress disabled for system")
        accepted = time.time() if now is None else float(now)
        event_ts = accepted if observation.ts is None else float(observation.ts)
        attributes = dict(observation.attributes)
        attributes["trust"] = "UNTRUSTED_EXTERNAL_DATA"
        attributes["source_system_id"] = observation.system_id
        attributes["gateway_source"] = source
        attributes.setdefault("correlation_key", f"gateway:{observation.system_id}:{observation.subject}")
        processed = self.processor.ingest(
            f"gateway:{observation.system_id}",
            {
                "ts": event_ts,
                "kind": observation.kind,
                "subject": observation.subject,
                "severity": observation.severity,
                "attributes": attributes,
            },
            ts=event_ts,
        )
        evidence = self.observability.evidence(
            kind="gateway_external_observation",
            payload={
                "system_id": observation.system_id,
                "signal_id": processed.signal.id,
                "kind": observation.kind,
                "subject": observation.subject,
                "trust": "UNTRUSTED_EXTERNAL_DATA",
                "source": source,
            },
            ts=accepted,
        )
        self.audit.append(
            actor="immune-gateway",
            action="gateway_ingress_accepted",
            payload={
                "system_id": observation.system_id,
                "signal_id": processed.signal.id,
                "evidence_id": evidence.id,
                "source": source,
            },
            now=accepted,
        )
        return IngressReceipt(observation.system_id, processed.signal.id, evidence.id, accepted)

    def ingest_signed(
        self,
        system_id: str,
        body: bytes,
        *,
        timestamp: int,
        nonce: str,
        signature: str,
        now: float | None = None,
    ) -> IngressReceipt:
        self.verify_signature(system_id, body, timestamp=timestamp, nonce=nonce, signature=signature, now=now)
        return self._accept(decode_observation(system_id, body), source="signed-push", now=now)

    def collect_once(self, system_id: str, *, timeout_seconds: float = 2.0, now: float | None = None) -> IngressReceipt | None:
        binding = self.config.binding(system_id)
        if binding.ingress != "pull":
            raise GatewayProtocolError("system is not configured for pull collection")
        adapter = self.adapters.get(system_id)
        if adapter is None:
            raise GatewayProtocolError("gateway pull adapter unavailable")
        observation = adapter.collect(timeout_seconds=timeout_seconds)
        if observation is None:
            return None
        if observation.system_id != system_id:
            raise GatewayProtocolError("adapter returned observation for another system")
        return self._accept(observation, source=f"adapter:{adapter.adapter_id}", now=now)
