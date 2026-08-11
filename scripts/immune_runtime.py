#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sistema Imunologico continuous sovereign runtime")
    parser.add_argument("--db", default=str(ROOT / "runtime" / "state.sqlite3"))
    parser.add_argument("--backups", default=str(ROOT / "runtime" / "backups"))
    parser.add_argument("--lock", default=str(ROOT / "runtime" / "supervisor.lock"))
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--backup-interval", type=float, default=300.0)
    parser.add_argument("--restore-drill-interval", type=float, default=900.0)
    parser.add_argument("--retention", type=int, default=5)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.interval <= 0:
        raise SystemExit("--interval must be positive")
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
