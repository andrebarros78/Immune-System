from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.audit import AuditLedger
from immune_core.identity import IdentityAuthority
from immune_provider_proxy.runtime import ProviderConfigurationError, ProviderRuntimeConfig
from immune_core.providers import ProviderRequest
from immune_core.storage import SQLiteStateStore


class CaptureHandler(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(n).decode("utf-8"))
        type(self).received.append((dict(self.headers), payload))
        content = json.dumps({"summary": "ok", "hypotheses": [], "recommended_tasks": [], "confidence": 0.8})
        body = json.dumps({"choices": [{"message": {"content": content}}]}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class Server:
    def __enter__(self):
        CaptureHandler.received = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}/v1/chat/completions"
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class ProviderRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = SQLiteStateStore(self.root / "state.db")
        self.audit = AuditLedger(self.store)
        self.identity = IdentityAuthority(b"I" * 32)

    def tearDown(self):
        os.environ.pop("IMMUNE_TEST_PROVIDER_KEY", None)
        self.store.close()
        self.tmp.cleanup()

    def write_config(self, provider: dict) -> Path:
        path = self.root / "providers.json"
        path.write_text(json.dumps({"schema": 1, "owner_scope": "immune-provider-proxy", "selection": "priority", "providers": [provider]}), encoding="utf-8")
        return path

    def base_provider(self, endpoint="http://127.0.0.1:9999/v1/chat/completions", model="model-a"):
        return {
            "id": "primary",
            "adapter": "openai-compatible-http",
            "enabled": True,
            "priority": 100,
            "locality": "external",
            "endpoint": endpoint,
            "model": model,
            "api_key_env": "IMMUNE_TEST_PROVIDER_KEY",
            "cost_per_call": 0.0,
            "request_options": {"thinking": {"type": "enabled"}},
        }

    def test_repository_current_provider_is_configuration_not_core_binding(self):
        cfg = ProviderRuntimeConfig.load(ROOT / "config" / "provider-runtime.json")
        self.assertEqual(cfg.owner_scope, "immune-provider-proxy")
        self.assertEqual(cfg.enabled_profiles()[0].model, "glm-4.7-flash")
        core_source = (ROOT / "immune_core" / "providers.py").read_text(encoding="utf-8")
        runtime_source = (ROOT / "immune_provider_proxy" / "runtime.py").read_text(encoding="utf-8")
        self.assertNotIn("glm-4.7", core_source.lower())
        self.assertNotIn("glm-4.7", runtime_source.lower())
        core_runtime = (ROOT / "immune_core" / "provider_runtime.py").read_text(encoding="utf-8")
        self.assertNotIn("api_key_env", core_runtime)
        self.assertNotIn("endpoint", core_runtime)

    def test_provider_can_be_swapped_only_by_configuration(self):
        first = ProviderRuntimeConfig.load(self.write_config(self.base_provider(model="model-one")))
        second = ProviderRuntimeConfig.load(self.write_config(self.base_provider(model="model-two")))
        self.assertEqual(first.providers[0].model, "model-one")
        self.assertEqual(second.providers[0].model, "model-two")

    def test_external_credential_must_live_in_immune_namespace(self):
        item = self.base_provider()
        item["api_key_env"] = "SHARED_PROVIDER_KEY"
        with self.assertRaises(ProviderConfigurationError):
            ProviderRuntimeConfig.load(self.write_config(item))

    def test_inline_secret_is_rejected(self):
        item = self.base_provider()
        item["api_key"] = "must-not-be-here"
        with self.assertRaises(ProviderConfigurationError):
            ProviderRuntimeConfig.load(self.write_config(item))

    def test_wrong_owner_scope_is_rejected(self):
        path = self.root / "bad.json"
        path.write_text(json.dumps({"schema": 1, "owner_scope": "shared", "providers": []}), encoding="utf-8")
        with self.assertRaises(ProviderConfigurationError):
            ProviderRuntimeConfig.load(path)

    def test_generic_adapter_uses_options_and_secret_without_exposing_value(self):
        with Server() as server:
            os.environ["IMMUNE_TEST_PROVIDER_KEY"] = "fake-key"
            cfg = ProviderRuntimeConfig.load(self.write_config(self.base_provider(endpoint=server.url)))
            manager = cfg.build_manager(self.identity, self.audit)
            result = manager.propose(ProviderRequest("m1", "diagnose"), now=2_000_000_000)
        self.assertEqual(result.summary, "ok")
        headers, body = CaptureHandler.received[-1]
        self.assertEqual(headers["Authorization"], "Bearer fake-key")
        self.assertEqual(body["thinking"], {"type": "enabled"})
        self.assertEqual(body["model"], "model-a")
        public = cfg.public_view()
        self.assertTrue(public["providers"][0]["credential_present"])
        self.assertNotIn("fake-key", json.dumps(public))


if __name__ == "__main__":
    unittest.main()
