from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import AuditLedger
from .engine import DurableLoopEngine
from .identity import IdentityAuthority
from .operations import CommandGateway, OperationalStore, ReadModel
from .policy import PolicyGuard
from .runbooks import RunbookRunner
from .storage import SQLiteStateStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="immune-cli")
    parser.add_argument("--db", required=True, help="Path to sovereign SQLite state")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "missions", "incidents", "tasks", "notifications", "human"):
        p = sub.add_parser(name)
        if name in {"incidents", "tasks"}:
            p.add_argument("--mission")
    cmd = sub.add_parser("command")
    cmd.add_argument("action", choices=("diagnose", "rollback", "cancel", "approve", "restore"))
    cmd.add_argument("--mission", required=True)
    cmd.add_argument("--token", required=True)
    cmd.add_argument("--target")
    cmd.add_argument("--checkpoint-id")
    cmd.add_argument("--human-exception-id")
    rb = sub.add_parser("runbook")
    rb.add_argument("runbook_id")
    rb.add_argument("--mission", required=True)
    rb.add_argument("--token", required=True)
    rb.add_argument("--parameter", action="append", default=[])
    return parser


def _pairs(values: list[str]) -> dict[str, str]:
    result = {}
    for item in values:
        if "=" not in item:
            raise SystemExit(f"invalid --parameter: {item}")
        key, value = item.split("=", 1)
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = SQLiteStateStore(Path(args.db))
    read = ReadModel(store)
    try:
        if args.command == "status":
            value = read.dashboard()
        elif args.command == "missions":
            value = read.missions()
        elif args.command == "incidents":
            value = read.incidents(args.mission)
        elif args.command == "tasks":
            value = read.tasks(args.mission)
        elif args.command == "notifications":
            value = read.notifications()
        elif args.command == "human":
            value = read.human_exceptions()
        else:
            secret_hex = __import__("os").environ.get("IMMUNE_IDENTITY_SECRET_HEX", "")
            if len(secret_hex) < 64:
                raise SystemExit("IMMUNE_IDENTITY_SECRET_HEX is required for write commands")
            identity = IdentityAuthority(bytes.fromhex(secret_hex))
            audit = AuditLedger(store)
            OperationalStore(store, audit).bind_identity(identity)
            policy = PolicyGuard.from_repository(Path.cwd(), identity, audit)
            engine = DurableLoopEngine(store, audit)
            gateway = CommandGateway(store, identity, policy, engine, audit)
            if args.command == "command":
                params = {}
                if args.checkpoint_id:
                    params["checkpoint_id"] = args.checkpoint_id
                value = gateway.submit(mission_id=args.mission, action=args.action, operator_token=args.token, target=args.target, parameters=params, human_exception_id=args.human_exception_id).__dict__
            else:
                value = RunbookRunner(gateway).execute(args.runbook_id, mission_id=args.mission, operator_token=args.token, parameters=_pairs(args.parameter)).__dict__
        print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
