#!/usr/bin/env python3
"""Gera catálogo de capacidade sem executar código de terceiros."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from immune_lab.admission import build_catalog


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", default="donors/LOCK.json")
    parser.add_argument("--evidence", default="donors/lab/evidence.json")
    parser.add_argument("--output", default="donors/lab/CAPABILITY_CATALOG.json")
    args = parser.parse_args()

    lock = json.loads(Path(args.lock).read_text(encoding="utf-8"))
    evidence_path = Path(args.evidence)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8")) if evidence_path.exists() else {}
    catalog = build_catalog(lock["donors"], evidence)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(catalog["summary"], sort_keys=True))
    return 0 if catalog["summary"]["rejected"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
