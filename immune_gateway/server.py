from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Type

from .contracts import GatewayError
from .ingress import GatewayIngress


def handler_for(ingress: GatewayIngress) -> Type[BaseHTTPRequestHandler]:
    class GatewayHandler(BaseHTTPRequestHandler):
        server_version = "ImmuneGateway/1"

        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._json(200, {"ok": True, "service": "immune-gateway"})
                return
            self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            prefix = "/v1/telemetry/"
            if not self.path.startswith(prefix):
                self._json(404, {"error": "not_found"})
                return
            system_id = self.path[len(prefix):].strip("/")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(400, {"error": "bad_length"})
                return
            if length < 1 or length > ingress.config.max_body_bytes:
                self._json(413, {"error": "body_limit"})
                return
            try:
                timestamp = int(self.headers.get("X-Immune-Timestamp", ""))
                nonce = self.headers.get("X-Immune-Nonce", "")
                signature = self.headers.get("X-Immune-Signature", "")
                body = self.rfile.read(length)
                receipt = ingress.ingest_signed(
                    system_id,
                    body,
                    timestamp=timestamp,
                    nonce=nonce,
                    signature=signature,
                )
                self._json(202, {"accepted": True, "signal_id": receipt.signal_id, "evidence_id": receipt.evidence_id})
            except (ValueError, GatewayError) as exc:
                self._json(403, {"accepted": False, "error": type(exc).__name__})

        def do_PUT(self) -> None:
            self._json(405, {"error": "method_not_allowed"})

        def do_DELETE(self) -> None:
            self._json(405, {"error": "method_not_allowed"})

        def do_PATCH(self) -> None:
            self._json(405, {"error": "method_not_allowed"})

        def log_message(self, fmt: str, *args) -> None:
            return

    return GatewayHandler


def build_server(ingress: GatewayIngress) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((ingress.config.bind_host, ingress.config.bind_port), handler_for(ingress))
