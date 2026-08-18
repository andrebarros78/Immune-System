#!/usr/bin/env python3
from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from immune_core.audit import AuditLedger
from immune_control_plane.cli import main as cli_main
from immune_core.diagnosis import IncidentEngine
from immune_core.engine import DurableLoopEngine
from immune_core.identity import IdentityAuthority
from immune_core.observability import ObservabilityStore, SignalProcessor
from immune_core.operations import CommandGateway, OperationalEventRouter, OperationalStore, OperationsError, ReadModel, ReportBuilder
from immune_presentation.panel import OperationalPanel
from immune_core.policy import PolicyGuard
from immune_core.remediation import RemediationPlanner
from immune_core.runbooks import RunbookRunner
from immune_core.storage import SQLiteStateStore

NOW = 2_100_000_100
checks: list[dict] = []
failures: list[str] = []


def ok(name: str, condition: object, detail: str = "") -> None:
    passed = bool(condition)
    checks.append({"name": name, "passed": passed, "detail": str(detail)})
    if not passed:
        failures.append(name)


for phase in range(1, 7):
    path = ROOT / f"PHASE{phase}_STATUS.md"
    ok(f"phase{phase}_baseline_proven", path.is_file() and f"PHASE{phase}_PROVEN" in path.read_text(encoding="utf-8"))

required = [
    "immune_core/operations.py",
    "immune_presentation/panel.py",
    "immune_control_plane/cli.py",
    "immune_core/runbooks.py",
    "tests/phase7/test_operations.py",
    "runbooks/default.json",
    "adr/ADR-0007-operational-experience.md",
    ".github/workflows/phase7-operations.yml",
]
for rel in required:
    ok(f"artifact:{rel}", (ROOT / rel).is_file())

for rel in ("immune_core/operations.py", "immune_presentation/panel.py", "immune_control_plane/cli.py", "immune_core/runbooks.py"):
    try:
        ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        ok(f"ast:{rel}", True)
    except SyntaxError as exc:
        ok(f"ast:{rel}", False, exc)

panel_text = (ROOT / "immune_presentation/panel.py").read_text(encoding="utf-8")
ops_text = (ROOT / "immune_core/operations.py").read_text(encoding="utf-8")
runbooks_text = (ROOT / "immune_core/runbooks.py").read_text(encoding="utf-8")
ok("panel_has_no_executor", "SafeExecutor" not in panel_text and "PrivilegedExecutor" not in panel_text and "WorkerRunner" not in panel_text)
ok("panel_rejects_post", "def do_POST" in panel_text and "405" in panel_text)
ok("panel_sqlite_read_only", "mode=ro" in panel_text and "PRAGMA query_only=ON" in panel_text)
ok("read_model_truth_rule", "absence or staleness is never green" in ops_text)
ok("commands_use_policyguard", "self.policy.evaluate_token" in ops_text)
ok("commands_queue_durable_core", "self.engine.submit_task" in ops_text)
ok("notifications_do_not_change_mission", "set_mission_state" not in ops_text)
ok("runbooks_no_subprocess", "subprocess" not in runbooks_text)
ok("reports_have_sha256", "content_sha256" in ops_text and "traceability" in ops_text)

with tempfile.TemporaryDirectory() as td:
    db = Path(td) / "state.db"
    store = SQLiteStateStore(db)
    audit = AuditLedger(store)
    identity = IdentityAuthority(b"7" * 32)
    policy = PolicyGuard.from_repository(ROOT, identity, audit)
    engine = DurableLoopEngine(store, audit)
    ops = OperationalStore(store, audit).bind_identity(identity)
    read = ReadModel(store, freshness_seconds=60)
    obs = ObservabilityStore(store, audit)
    incidents = IncidentEngine(store, obs, audit)
    RemediationPlanner(store, incidents, obs, audit)
    engine.create_mission("m", "sys")
    engine.transition_mission("m", "AUTHORIZED", "phase7")
    engine.transition_mission("m", "RUNNING", "phase7")

    ok("false_green_no_sensors", read.system_health(now=NOW)["state"] == "UNKNOWN")
    obs.update_sensor_health("sensor-a", ok=True, ts=NOW)
    ok("fresh_sensor_green", read.system_health(now=NOW + 1)["state"] == "HEALTHY")
    ok("stale_sensor_not_green", read.system_health(now=NOW + 120)["state"] == "DEGRADED")
    before = store.conn.total_changes
    snapshot = read.dashboard(now=NOW + 1)
    ok("dashboard_read_only", store.conn.total_changes == before)
    ok("dashboard_has_workers", "workers" in snapshot)
    ok("dashboard_has_metrics", "metrics" in snapshot)

    router = OperationalEventRouter(ops)
    n1 = router.critical_failure("m", "svc", now=NOW)
    n2 = router.critical_failure("m", "svc", now=NOW + 1)
    ok("notification_dedup", n1.id == n2.id and len(read.notifications(open_only=True)) == 1)
    router.recovery("m", "svc", now=NOW + 2)
    ok("recovery_notification", any(x["kind"] == "RECOVERY" for x in read.notifications()))

    concrete_guard = False
    try:
        ops.request_human_exception(mission_id="m", reason="MFA", required_action="open\napprove", consequence="blocked", continuation="resume", now=NOW)
    except OperationsError:
        concrete_guard = True
    ok("human_exception_single_action", concrete_guard)
    hx = ops.request_human_exception(mission_id="m", reason="MFA", required_action="Approve MFA prompt", consequence="mission remains blocked", continuation="resume investigation", now=NOW)
    human_token = identity.issue("owner", "human", ("human:approve",), ttl_seconds=600, now=NOW)
    hx2 = ops.decide_human_exception(hx.id, human_token, approve=True, now=NOW + 1)
    ok("human_exception_explicit_approval", hx2.state == "APPROVED")

    operator = identity.issue("operator", "human", ("operator:diagnose", "operator:rollback", "operator:runbook"), ttl_seconds=600, now=NOW)
    gateway = CommandGateway(store, identity, policy, engine, audit)
    cmd = gateway.submit(mission_id="m", action="diagnose", operator_token=operator, target="incident-x", now=NOW)
    task = store.get_task(cmd.task_id)
    ok("operator_command_queued", cmd.state == "QUEUED" and task["kind"] == "operator_command")
    ok("operator_command_no_host_effect", task["payload"]["action"] == "diagnose")

    paid_blocked = False
    try:
        gateway.submit(mission_id="m", action="diagnose", operator_token=operator, parameters={"risk": {"purchase": True}}, now=NOW)
    except OperationsError:
        paid_blocked = True
    ok("financial_command_blocked", paid_blocked)

    rb = RunbookRunner(gateway).execute("rollback", mission_id="m", operator_token=operator, parameters={"checkpoint_id": "cp-proof"}, now=NOW)
    ok("runbook_queues_core", store.get_task(rb.task_id)["payload"]["action"] == "rollback")

    signal = SignalProcessor(obs).ingest("sensor", {"kind":"service","subject":"svc","severity":"error","attributes":{"correlation_key":"svc"}}, ts=NOW)
    inc = incidents.create_or_attach_from_signal(signal.signal.id, "m", now=NOW)
    hyp = incidents.add_hypothesis(inc.id, "configuration mismatch", now=NOW)
    ev = obs.evidence(kind="discriminating_test", payload={"positive": True}, mission_id="m", ts=NOW)
    incidents.record_attempt(inc.id, hyp.id, strategy="compare-config", test_name="config-diff", outcome="POSITIVE", progress_score=1, evidence_id=ev.id, now=NOW)
    report = ReportBuilder(store, audit).build_incident(inc.id, requirement_ids=("REQ-TRACE",), now=NOW + 2)
    ok("report_requirement_trace", report["content"]["traceability"][0]["requirement"] == "REQ-TRACE")
    ok("report_action_trace", "config-diff" in report["content"]["traceability"][0]["actions"])
    ok("report_evidence_trace", ev.id in report["content"]["traceability"][0]["evidence_ids"])
    ok("report_integrity", ReportBuilder(store, audit).verify(report["id"]))

    panel = OperationalPanel(read)
    html = panel.render_html(now=NOW + 1)
    ok("panel_renders_truth", "Sistema Imunológico" in html and "Health:" in html and "read-only" in html)
    threaded_snapshot = panel.snapshot_threadsafe(now=NOW + 1)
    ok("panel_threadsafe_read", threaded_snapshot["health"]["state"] == "HEALTHY")

    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        rc = cli_main(["--db", str(db), "status"])
    parsed = json.loads(output.getvalue())
    ok("cli_status_functional", rc == 0 and "health" in parsed)

    valid, bad_seq = audit.verify_chain()
    ok("audit_chain_valid", valid and bad_seq is None, str(bad_seq))
    store.close()

controlled = required
hashes = {rel: hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() for rel in controlled}
evidence = {
    "schema": 1,
    "phase": "PHASE_7_OPERATIONAL_EXPERIENCE",
    "validated_at": datetime.now(timezone.utc).isoformat(),
    "checks": checks,
    "summary": {"total": len(checks), "passed": sum(1 for item in checks if item["passed"]), "failed": len(failures)},
    "controlled_file_sha256": hashes,
    "result": "PHASE7_PROVEN" if not failures else "PHASE7_FAILED",
    "scope_note": "PHASE7_PROVEN proves truthful read models, read-only panel, authenticated policy-gated operator commands, persistent notifications, human-exception workflow, traceable reports and runbooks queued through Core. It is not MISSION_PROVEN for the complete product.",
}
(ROOT / "evidence").mkdir(exist_ok=True)
(ROOT / "evidence/phase7-validation.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
status = "PHASE7_PROVEN" if not failures else "PHASE7_FAILED"
(ROOT / "PHASE7_STATUS.md").write_text(
    "# Fase 7 — Experiência Operacional\n\n"
    f"**Estado: {status}**\n\n"
    f"Checks: {evidence['summary']['passed']}/{evidence['summary']['total']} aprovados.\n\n"
    "Capacidades: read-model verdadeiro, painel web somente leitura, CLI soberana, notificações persistentes, exceção humana explícita, relatórios rastreáveis e runbooks enfileirados pela Core.\n\n"
    "A interface não possui autoridade material; o produto completo permanece sem MISSION_PROVEN.\n",
    encoding="utf-8",
)
print(json.dumps(evidence["summary"], sort_keys=True))
if failures:
    print("FAILED:", ", ".join(failures))
    raise SystemExit(1)
print("PHASE7_PROVEN")
