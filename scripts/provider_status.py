from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.autonomy import InternalAgentRegistry
from immune_provider_proxy.runtime import ProviderRuntimeConfig


def main() -> int:
    parser = argparse.ArgumentParser(prog="immune-provider-status")
    parser.add_argument("--config", default="config/provider-runtime.json")
    args = parser.parse_args()
    cfg = ProviderRuntimeConfig.load(Path(args.config))
    value = {
        "provider_runtime": cfg.public_view(),
        "internal_agents": list(InternalAgentRegistry().public_view()),
    }
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
