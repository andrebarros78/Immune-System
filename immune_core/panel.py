from __future__ import annotations

import html
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .operations import ReadModel


class PanelError(RuntimeError):
    pass


class _ReadOnlyStore:
    def __init__(self, path: str):
        if path == ":memory:":
            raise PanelError("HTTP panel requires file-backed SQLite state")
        self.path = path
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA query_only=ON")


class OperationalPanel:
    """Read-only dashboard projection. It has no write-capable Core object."""

    def __init__(self, read_model: ReadModel):
        self.read_model = read_model

    def snapshot(self, *, now: float | None = None) -> dict[str, Any]:
        return self.read_model.dashboard(now=now)

    def snapshot_threadsafe(self, *, now: float | None = None) -> dict[str, Any]:
        ro = _ReadOnlyStore(str(self.read_model.store.path))
        try:
            return ReadModel(ro, freshness_seconds=self.read_model.freshness_seconds).dashboard(now=now)
        finally:
            ro.conn.close()

    @staticmethod
    def _render(data: dict[str, Any]) -> str:
        health = data["health"]["state"]
        rows = "".join(
            f"<tr><td>{html.escape(str(m['id']))}</td><td>{html.escape(str(m['state']))}</td><td>{html.escape(str(m['system_id']))}</td></tr>"
            for m in data["missions"]
        )
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>Immune System</title></head><body>"
            f"<h1>Sistema Imunológico</h1><p id='health'>Health: {html.escape(health)}</p>"
            f"<p>{html.escape(data['truth_rule'])}</p>"
            "<table><thead><tr><th>Mission</th><th>State</th><th>System</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            "<p>Operational panel is read-only. Commands must use the authenticated Core command endpoint/CLI.</p>"
            "</body></html>"
        )

    def render_html(self, *, now: float | None = None) -> str:
        return self._render(self.snapshot(now=now))

    def render_html_threadsafe(self, *, now: float | None = None) -> str:
        return self._render(self.snapshot_threadsafe(now=now))


def serve_read_only(panel: OperationalPanel, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/api/status":
                body = json.dumps(panel.snapshot_threadsafe(), ensure_ascii=False, sort_keys=True).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
            elif self.path in {"/", "/index.html"}:
                body = panel.render_html_threadsafe().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
            else:
                body = b'{"error":"not found"}'
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            body = b'{"error":"read-only panel; use authenticated Core command channel"}'
            self.send_response(405)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, int(port)), Handler)
