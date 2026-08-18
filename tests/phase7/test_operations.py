from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from immune_core.audit import AuditLedger
from immune_core.diagnosis import IncidentEngine
from immune_core.engine import DurableLoopEngine
from immune_core.identity import IdentityAuthority
from immune_core.observability import ObservabilityStore, SignalProcessor
from immune_core.operations import CommandGateway, OperationalStore, OperationsError, ReadModel, ReportBuilder
from immune_presentation.panel import OperationalPanel, serve_read_only
from immune_core.policy import PolicyGuard
from immune_core.remediation import RemediationPlanner
from immune_core.runbooks import RunbookRunner
from immune_core.storage import SQLiteStateStore


ROOT = Path(__file__).resolve().parents[2]
NOW = 2_100_000_000


class Phase7Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStateStore(Path(self.tmp.name) / "state.db")
        self.audit = AuditLedger(self.store)
        self.identity = IdentityAuthority(b"7" * 32)
        self.policy = PolicyGuard.from_repository(ROOT, self.identity, self.audit)
        self.engine = DurableLoopEngine(self.store, self.audit)
        self.ops = OperationalStore(self.store, self.audit).bind_identity(self.identity)
        self.read = ReadModel(self.store, freshness_seconds=60)
        self.obs = ObservabilityStore(self.store, self.audit)
        self.incidents = IncidentEngine(self.store, self.obs, self.audit)
        self.remediation = RemediationPlanner(self.store, self.incidents, self.obs, self.audit)
        self.engine.create_mission("m", "sys")
        self.engine.transition_mission("m", "AUTHORIZED", "phase7")
        self.engine.transition_mission("m", "RUNNING", "phase7")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def token(self, *scopes):
        return self.identity.issue("operator", "human", scopes, ttl_seconds=600, now=NOW)

    def test_false_green_is_impossible_without_fresh_evidence(self):
        unknown = self.read.system_health(now=NOW)
        self.assertEqual(unknown["state"], "UNKNOWN")
        self.obs.update_sensor_health("s", ok=True, ts=NOW)
        healthy = self.read.system_health(now=NOW + 10)
        self.assertEqual(healthy["state"], "HEALTHY")
        self.assertTrue(healthy["fresh"])
        stale = self.read.system_health(now=NOW + 120)
        self.assertEqual(stale["state"], "DEGRADED")
        self.assertFalse(stale["fresh"])

    def test_failed_sensor_overrides_green(self):
        self.obs.update_sensor_health("a", ok=True, ts=NOW)
        for t in (NOW, NOW + 1, NOW + 2):
            self.obs.update_sensor_health("b", ok=False, error="boom", ts=t)
        health = self.read.system_health(now=NOW + 3)
        self.assertEqual(health["state"], "FAILED")
        self.assertIn("b", health["failed"])

    def test_read_model_does_not_write(self):
        before = self.store.conn.total_changes
        snapshot = self.read.dashboard(now=NOW)
        after = self.store.conn.total_changes
        self.assertEqual(before, after)
        self.assertEqual(snapshot["health"]["state"], "UNKNOWN")

    def test_notifications_are_persistent_and_deduplicated(self):
        a = self.ops.notify(kind="CRITICAL_FAILURE", severity="CRITICAL", subject="svc", payload={"x": 1}, mission_id="m", now=NOW)
        b = self.ops.notify(kind="CRITICAL_FAILURE", severity="CRITICAL", subject="svc", payload={"x": 2}, mission_id="m", now=NOW + 1)
        self.assertEqual(a.id, b.id)
        self.assertEqual(len(self.read.notifications(open_only=True)), 1)
        self.ops.close_notification(a.id, now=NOW + 2)
        self.assertEqual(self.read.notifications(open_only=True), [])

    def test_human_exception_requires_single_concrete_action_and_explicit_identity(self):
        with self.assertRaises(OperationsError):
            self.ops.request_human_exception(mission_id="m", reason="MFA", required_action="Open app\nApprove", consequence="blocked", continuation="resume", now=NOW)
        x = self.ops.request_human_exception(mission_id="m", reason="MFA", required_action="Approve the MFA prompt", consequence="mission remains blocked", continuation="resume investigation", now=NOW)
        self.assertEqual(x.state, "PENDING")
        with self.assertRaises(Exception):
            self.ops.decide_human_exception(x.id, self.token("operator:approve"), approve=True, now=NOW + 1)
        decided = self.ops.decide_human_exception(x.id, self.token("human:approve"), approve=True, now=NOW + 1)
        self.assertEqual(decided.state, "APPROVED")

    def test_operator_command_passes_policy_and_queues_core_task(self):
        gateway = CommandGateway(self.store, self.identity, self.policy, self.engine, self.audit)
        cmd = gateway.submit(mission_id="m", action="diagnose", operator_token=self.token("operator:diagnose"), target="incident-x", now=NOW)
        self.assertEqual(cmd.state, "QUEUED")
        task = self.store.get_task(cmd.task_id)
        self.assertEqual(task["kind"], "operator_command")
        self.assertEqual(task["payload"]["action"], "diagnose")

    def test_financial_operator_command_is_blocked(self):
        gateway = CommandGateway(self.store, self.identity, self.policy, self.engine, self.audit)
        with self.assertRaises(OperationsError):
            gateway.submit(mission_id="m", action="diagnose", operator_token=self.token("operator:diagnose"), parameters={"risk": {"purchase": True}}, now=NOW)

    def test_runbook_is_executable_only_through_core_queue(self):
        gateway = CommandGateway(self.store, self.identity, self.policy, self.engine, self.audit)
        runner = RunbookRunner(gateway)
        with self.assertRaises(OperationsError):
            runner.execute("rollback", mission_id="m", operator_token=self.token("operator:rollback"), parameters={}, now=NOW)
        ref = runner.execute("rollback", mission_id="m", operator_token=self.token("operator:rollback"), parameters={"checkpoint_id": "cp-verified"}, now=NOW)
        task = self.store.get_task(ref.task_id)
        self.assertEqual(task["payload"]["action"], "rollback")
        self.assertEqual(task["payload"]["parameters"]["checkpoint_id"], "cp-verified")

    def test_panel_is_read_only_http(self):
        self.obs.update_sensor_health("s", ok=True, ts=NOW)
        panel = OperationalPanel(self.read)
        server = serve_read_only(panel, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            data = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status").read())
            self.assertIn(data["health"]["state"], {"HEALTHY", "DEGRADED"})
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/status", data=b"{}", method="POST")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req)
            self.assertEqual(ctx.exception.code, 405)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_panel_failure_does_not_stop_core(self):
        class BrokenRead:
            def dashboard(self, **kwargs):
                raise RuntimeError("panel died")
        panel = OperationalPanel(BrokenRead())
        with self.assertRaises(RuntimeError):
            panel.snapshot()
        task_id = self.engine.submit_task("m", "proof", {"ok": True}, idempotency_key="after-panel-crash", now=NOW)
        self.assertEqual(self.store.get_task(task_id)["state"], "QUEUED")

    def test_report_links_requirement_action_test_evidence(self):
        signal = SignalProcessor(self.obs).ingest("sensor", {"kind": "service", "subject": "svc", "severity": "error", "attributes": {"correlation_key": "svc"}}, ts=NOW)
        incident = self.incidents.create_or_attach_from_signal(signal.signal.id, "m", now=NOW)
        hypothesis = self.incidents.add_hypothesis(incident.id, "config mismatch", now=NOW)
        ev = self.obs.evidence(kind="discriminating_test", payload={"positive": True}, mission_id="m", ts=NOW)
        self.incidents.record_attempt(incident.id, hypothesis.id, strategy="compare-config", test_name="config-diff", outcome="POSITIVE", progress_score=1, evidence_id=ev.id, now=NOW)
        report = ReportBuilder(self.store, self.audit).build_incident(incident.id, requirement_ids=("REQ-13",), now=NOW + 1)
        trace = report["content"]["traceability"][0]
        self.assertEqual(trace["requirement"], "REQ-13")
        self.assertIn("config-diff", trace["actions"])
        self.assertIn(ev.id, trace["evidence_ids"])
        self.assertTrue(ReportBuilder(self.store, self.audit).verify(report["id"]))


if __name__ == "__main__":
    unittest.main()
