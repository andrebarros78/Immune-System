#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_gateway.runtime_config import GatewayRuntimeConfig


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Public, secret-free Immune Gateway status")
    p.add_argument("--config", default=str(ROOT / "config" / "gateway-runtime.json"))
    args = p.parse_args(argv)
    config = GatewayRuntimeConfig.load(args.config)
    status = config.public_status()
    status["boundary"] = {
        "external_input": "data-only",
        "external_core_identity": False,
        "external_control_api": False,
        "protected_system_specific_code_location": "immune_gateway.adapters",
        "core_specific_protocol_dependency": False,
    }
    print(json.dumps(status, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
