from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from immune_core.audit import AuditLedger
from immune_core.identity import IdentityAuthority
from immune_core.policy import PolicyGuard
from immune_core.storage import SQLiteStateStore
from immune_gateway.contracts import GatewayProtocolError, GatewayReplayError, GatewayObservation
from immune_gateway.ingress import GatewayIngress
from immune_gateway.protocol import external_signature
from immune_gateway.runtime_config import GatewayRuntimeConfig

ROOT = Path(__file__).resolve().parents[1]
NOW = 2_300_000_000


class FakeAdapter:
    adapter_id = "fake-adapter"
    system_id = "protected-a"

    def collect(self, *, timeout_seconds: float = 2.0):
        return GatewayObservation(self.system_id, "health", "service-a", "info", {"ok": True}, NOW)

    def execute(self, action, parameters, *, timeout_seconds: float = 10.0):
        return {"ok": True, "external_reference": "ref-1", "detail": "applied"}


class ImmuneGatewayIngressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = SQLiteStateStore(self.root / "state.sqlite3")
        self.audit = AuditLedger(self.store)
        self.identity = IdentityAuthority(b"I" * 32)
        self.policy = PolicyGuard.from_repository(ROOT, self.identity, self.audit)
        self.secret_env = "IMMUNE_GATEWAY_PROTECTED_A_SECRET"
        os.environ[self.secret_env] = "S" * 48

    def tearDown(self):
        os.environ.pop(self.secret_env, None)
        self.store.close()
        self.tmp.cleanup()

    def config(self, *, ingress="push-signed"):
        data = {
            "schema": 1,
            "owner_scope": "immune-gateway",
            "bind": {"host": "127.0.0.1", "port": 4020},
            "limits": {"max_body_bytes": 65536, "max_clock_skew_seconds": 60, "nonce_ttl_seconds": 300},
            "systems": [{"id": "protected-a", "adapter": "fake-adapter", "enabled": True, "ingress": ingress, "config": {}}],
        }
        if ingress == "push-signed":
            data["systems"][0]["peer_secret_env"] = self.secret_env
        path = self.root / f"gateway-{ingress}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return GatewayRuntimeConfig.load(path)

    @staticmethod
    def body():
        return json.dumps({"kind": "service.health", "subject": "service-a", "severity": "error", "attributes": {"ok": False}}, separators=(",", ":")).encode("utf-8")

    def test_signed_ingress_is_data_only_and_untrusted(self):
        ingress = GatewayIngress(self.store, self.audit, self.config(), {})
        body = self.body()
        nonce = "nonce-0123456789abcdef"
        signature = external_signature(os.environ[self.secret_env].encode(), "protected-a", NOW, nonce, body)
        receipt = ingress.ingest_signed("protected-a", body, timestamp=NOW, nonce=nonce, signature=signature, now=NOW)
        row = self.store.conn.execute("SELECT attributes_json FROM obs_signals WHERE id=?", (receipt.signal_id,)).fetchone()
        attrs = json.loads(row["attributes_json"])
        self.assertEqual(attrs["trust"], "UNTRUSTED_EXTERNAL_DATA")
        self.assertEqual(attrs["source_system_id"], "protected-a")
        self.assertTrue(ingress.observability.verify_evidence(receipt.evidence_id))

    def test_replay_is_rejected(self):
        ingress = GatewayIngress(self.store, self.audit, self.config(), {})
        body = self.body()
        nonce = "nonce-0123456789abcdef"
        signature = external_signature(os.environ[self.secret_env].encode(), "protected-a", NOW, nonce, body)
        ingress.ingest_signed("protected-a", body, timestamp=NOW, nonce=nonce, signature=signature, now=NOW)
        with self.assertRaises(GatewayReplayError):
            ingress.ingest_signed("protected-a", body, timestamp=NOW, nonce=nonce, signature=signature, now=NOW)

    def test_external_control_fields_are_rejected(self):
        ingress = GatewayIngress(self.store, self.audit, self.config(), {})
        body = json.dumps({"kind": "health", "subject": "x", "attributes": {}, "control": "forbidden"}).encode()
        nonce = "nonce-abcdef0123456789"
        signature = external_signature(os.environ[self.secret_env].encode(), "protected-a", NOW, nonce, body)
        with self.assertRaises(GatewayProtocolError):
            ingress.ingest_signed("protected-a", body, timestamp=NOW, nonce=nonce, signature=signature, now=NOW)

    def test_pull_adapter_enters_only_through_gateway(self):
        adapter = FakeAdapter()
        ingress = GatewayIngress(self.store, self.audit, self.config(ingress="pull"), {"protected-a": adapter})
        receipt = ingress.collect_once("protected-a", now=NOW)
        self.assertEqual(receipt.system_id, "protected-a")

    def test_core_wmcp2_file_is_networkless_tombstone(self):
        text = (ROOT / "immune_core" / "wmcp2_adapter.py").read_text(encoding="utf-8")
        self.assertNotIn("socket", text)
        self.assertNotIn("urllib", text)
        self.assertNotIn("8766", text)

    def test_public_status_does_not_expose_secret_value(self):
        status = self.config().public_status()
        encoded = json.dumps(status)
        self.assertNotIn(os.environ[self.secret_env], encoded)
        self.assertTrue(status["systems"][0]["credential_present"])


if __name__ == "__main__":
    unittest.main()


def test_http_gateway_has_no_core_or_egress_dependency():
    source = (ROOT / "immune_gateway" / "server.py").read_text(encoding="utf-8")
    assert "GatewayEgress" not in source
    assert "PolicyGuard" not in source
    assert "IdentityAuthority" not in source
    assert "/v1/telemetry/" in source


def test_default_gateway_config_has_no_protected_system_targets():
    config = GatewayRuntimeConfig.load(ROOT / "config" / "gateway-runtime.json")
    assert config.systems == ()


def test_live_provider_test_config_isolated_to_zai():
    raw = json.loads((ROOT / "config" / "provider-live-test.json").read_text(encoding="utf-8"))
    providers = raw.get("providers", [])
    assert len(providers) == 1
    endpoint = str(providers[0].get("endpoint", ""))
    assert endpoint.startswith("https://api.z.ai/")
    encoded = json.dumps(raw).lower()
    for forbidden in ("127.0.0.1", "localhost", "windows-mcp", "wmcp", "tunel-core", "tunnel-core"):
        assert forbidden not in encoded
