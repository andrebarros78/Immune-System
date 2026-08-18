#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.audit import AuditLedger
from immune_core.continuous import ContinuousSupervisor, SupervisorLock
from immune_core.engine import DurableLoopEngine
from immune_core.observability import ObservabilityStore
from immune_core.state_backup import StateBackupManager
from immune_core.storage import SQLiteStateStore
from immune_fortress.bootstrap import FortressBootGate
from immune_fortress.root_trust import BrainRootOfTrust, ExternalHMACRootKey, RootManifest


CONTAINED_EXIT = 23


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sistema Imunologico continuous sovereign runtime")
    parser.add_argument("--db", default=str(ROOT / "runtime" / "state.sqlite3"))
    parser.add_argument("--backups", default=str(ROOT / "runtime" / "backups"))
    parser.add_argument("--lock", default=str(ROOT / "runtime" / "supervisor.lock"))
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--backup-interval", type=float, default=300.0)
    parser.add_argument("--restore-drill-interval", type=float, default=900.0)
    parser.add_argument("--retention", type=int, default=5)
    parser.add_argument("--fortress-manifest", help="External signed root manifest JSON")
    parser.add_argument("--fortress-signature", help="External root-manifest signature file")
    parser.add_argument("--fortress-min-generation", type=int, default=1)
    parser.add_argument("--closed-lab-root", action="store_true", help="Allow ephemeral HMAC root only for isolated lab/CI")
    parser.add_argument("--attest-only", action="store_true", help="Verify fortress boot chain and exit before opening runtime state")
    return parser


def _load_manifest(path: str | Path) -> RootManifest:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("fortress manifest must be an object")
    files = raw.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("fortress manifest files are required")
    return RootManifest(
        int(raw["generation"]),
        str(raw["source_commit"]),
        {str(k): str(v) for k, v in files.items()},
        str(raw["signer"]),
    )


def attest_fortress(args: argparse.Namespace) -> tuple[bool, str]:
    if not args.fortress_manifest or not args.fortress_signature:
        return False, "root attestation files are required"
    if not args.closed_lab_root:
        return False, "physical runtime requires hardware-backed RootKeyProvider"
    secret_hex = os.environ.get("IMMUNE_FORTRESS_ROOT_KEY_HEX", "")
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError:
        return False, "closed-lab root key encoding invalid"
    if len(secret) < 32:
        return False, "closed-lab root key missing or weak"
    try:
        manifest = _load_manifest(args.fortress_manifest)
        signature = Path(args.fortress_signature).read_text(encoding="utf-8").strip()
        trust = BrainRootOfTrust(ROOT, ExternalHMACRootKey(secret))
        result = FortressBootGate(trust).attest(
            manifest,
            signature,
            minimum_generation=args.fortress_min_generation,
            require_hardware_backed=False,
        )
    except Exception as exc:
        return False, f"root attestation load failure: {type(exc).__name__}"
    return result.operational, result.reason


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.interval <= 0:
        raise SystemExit("--interval must be positive")

    # This gate is intentionally before db.parent.mkdir / SQLiteStateStore: no
    # sovereign state is opened or created before Root of Trust succeeds.
    operational, reason = attest_fortress(args)
    if not operational:
        print(f"BRAIN_FORTRESS_MODE=CONTAINED_READ_ONLY reason={reason}")
        return CONTAINED_EXIT
    print("BRAIN_FORTRESS_BOOT_ATTESTED=true")
    if args.attest_only:
        return 0

    db = Path(args.db).resolve()
    db.parent.mkdir(parents=True, exist_ok=True)
    store = SQLiteStateStore(db)
    audit = AuditLedger(store)
    engine = DurableLoopEngine(store, audit)
    observability = ObservabilityStore(store, audit)
    backups = StateBackupManager(store, args.backups, audit)

    def db_integrity() -> bool:
        row = store.conn.execute("PRAGMA integrity_check").fetchone()
        return bool(row and str(row[0]).lower() == "ok")

    def audit_integrity() -> bool:
        valid, bad_seq = audit.verify_chain()
        return valid and bad_seq is None

    supervisor = ContinuousSupervisor(
        store,
        engine,
        observability,
        audit,
        backups,
        probes={"sqlite": db_integrity, "audit-chain": audit_integrity},
        backup_interval_seconds=args.backup_interval,
        restore_drill_interval_seconds=args.restore_drill_interval,
        backup_retention=args.retention,
    )
    lock = SupervisorLock(args.lock)
    try:
        lock.acquire()
        supervisor.boot()
        while True:
            supervisor.tick()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        supervisor.stop()
        return 0
    finally:
        lock.release()
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
