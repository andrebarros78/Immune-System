#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.audit import AuditLedger
from immune_core.storage import SQLiteStateStore
from immune_gateway.adapters import HTTPJSONGatewayAdapter, TCPHealthGatewayAdapter, WMCP2GatewayAdapter
from immune_gateway.ingress import GatewayIngress
from immune_gateway.runtime_config import GatewayRuntimeConfig
from immune_gateway.server import build_server


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Exclusive network boundary for Sistema Imunologico")
    p.add_argument("--db", default=str(ROOT / "runtime" / "state.sqlite3"))
    p.add_argument("--config", default=str(ROOT / "config" / "gateway-runtime.json"))
    p.add_argument("--poll-interval", type=float, default=2.0)
    return p


def build_adapters(config: GatewayRuntimeConfig):
    adapters = {}
    for binding in config.systems:
        if not binding.enabled:
            continue
        options = dict(binding.config)
        if binding.adapter == "wmcp2-local":
            adapters[binding.system_id] = WMCP2GatewayAdapter(**options)
        elif binding.adapter == "tcp-health":
            adapters[binding.system_id] = TCPHealthGatewayAdapter(binding.system_id, adapter_id=binding.adapter, **options)
        elif binding.adapter == "http-json":
            adapters[binding.system_id] = HTTPJSONGatewayAdapter(binding.system_id, binding.adapter, **options)
    return adapters


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.poll_interval <= 0:
        raise SystemExit("--poll-interval must be positive")
    config = GatewayRuntimeConfig.load(args.config)
    db = Path(args.db).resolve()
    db.parent.mkdir(parents=True, exist_ok=True)
    store = SQLiteStateStore(db)
    audit = AuditLedger(store)
    ingress = GatewayIngress(store, audit, config, build_adapters(config))
    server = build_server(ingress)
    thread = threading.Thread(target=server.serve_forever, name="immune-gateway-http", daemon=True)
    thread.start()
    audit.append(actor="immune-gateway", action="gateway_runtime_started", payload={"bind_host": config.bind_host, "bind_port": config.bind_port})
    try:
        while True:
            for binding in config.systems:
                if binding.enabled and binding.ingress == "pull":
                    try:
                        ingress.collect_once(binding.system_id)
                    except Exception as exc:
                        audit.append(actor="immune-gateway", action="gateway_pull_failed", payload={"system_id": binding.system_id, "error": type(exc).__name__})
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        audit.append(actor="immune-gateway", action="gateway_runtime_stopped", payload={})
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
