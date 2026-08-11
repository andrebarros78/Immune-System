from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from immune_core.acceptance import REQUIRED_GATES, MissionProofEngine
from immune_core.audit import AuditLedger
from immune_core.engine import DurableLoopEngine
from immune_core.identity import IdentityAuthority, IdentityError
from immune_core.policy import PolicyGuard
from immune_core.storage import SQLiteStateStore, StateError


class FoundationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "state.db"
        self.store = SQLiteStateStore(self.db)
        self.audit = AuditLedger(self.store)
        self.identity = IdentityAuthority(b"x" * 32)
        self.constitution = Path(self.tmp.name) / "IMUNE-DNA-001.md"
        self.constitution.write_text("IMUNE-DNA-001\n", encoding="utf-8")
        self.constitution_hash = hashlib.sha256(self.constitution.read_bytes()).hexdigest()
        self.guard = PolicyGuard(
            self.identity,
            self.audit,
            constitution_path=self.constitution,
            expected_constitution_sha256=self.constitution_hash,
        )
        self.engine = DurableLoopEngine(self.store, self.audit)
        self.engine.create_mission("m1", "s1")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def token(self, scopes=("execute:safe",), now=1000, ttl=300):
        return self.identity.issue("worker-1", "worker", scopes, ttl_seconds=ttl, now=now)

    def base_request(self):
        return {
            "mission_id": "m1",
            "action": "safe_op",
            "required_scope": "execute:safe",
            "mission_authorized": True,
            "system_authorized": True,
            "scope_ok": True,
        }

    def test_identity_valid_and_tamper_rejected(self):
        token = self.token()
        principal = self.identity.verify(token, required_scope="execute:safe", now=1001)
        self.assertEqual(principal.subject, "worker-1")
        altered = token[:-1] + ("A" if token[-1] != "A" else "B")
        with self.assertRaises(IdentityError):
            self.identity.verify(altered, now=1001)

    def test_identity_expiry(self):
        token = self.token(ttl=2)
        with self.assertRaises(IdentityError):
            self.identity.verify(token, now=1002)

    def test_policy_safe_action_permitted_and_audited(self):
        decision = self.guard.evaluate_token(self.token(), self.base_request(), now=1001)
        self.assertEqual(decision.decision, "PERMITIR")
        self.assertEqual(self.audit.count(), 2)  # mission_created + policy decision

    def test_policy_fail_closed_on_scope(self):
        req = self.base_request()
        req["scope_ok"] = False
        decision = self.guard.evaluate_token(self.token(), req, now=1001)
        self.assertEqual(decision.decision, "BLOQUEAR")

    def test_policy_paid_action_human_gate(self):
        req = self.base_request()
        req["purchase"] = True
        decision = self.guard.evaluate_token(self.token(), req, now=1001)
        self.assertEqual(decision.decision, "EXIGIR_APROVAÇÃO_HUMANA")

    def test_policy_material_change_requires_checkpoint(self):
        req = self.base_request()
        req["material_change"] = True
        decision = self.guard.evaluate_token(self.token(), req, now=1001)
        self.assertEqual(decision.decision, "EXIGIR_CHECKPOINT")

    def test_policy_security_control_disable_blocked(self):
        req = self.base_request()
        req["disables_security_control"] = True
        decision = self.guard.evaluate_token(self.token(), req, now=1001)
        self.assertEqual(decision.decision, "BLOQUEAR")

    def test_policy_constitution_tamper_fail_closed(self):
        self.constitution.write_text("tampered", encoding="utf-8")
        decision = self.guard.evaluate_token(self.token(), self.base_request(), now=1001)
        self.assertEqual(decision.decision, "BLOQUEAR")

    def test_policy_donor_requires_all_gates(self):
        req = self.base_request()
        req.update({"donor_component": True, "open_source": False})
        self.assertEqual(self.guard.evaluate_token(self.token(), req, now=1001).decision, "BLOQUEAR")
        req.update({
            "open_source": True,
            "license_verified": True,
            "origin_pinned": True,
            "artifact_hash_verified": True,
            "security_scanned": True,
            "laboratory_approved": True,
            "authority": "adapter-only",
        })
        decision = self.guard.evaluate_token(self.token(), req, now=1001)
        self.assertEqual(decision.decision, "PERMITIR_COM_RESTRIÇÕES")
        self.assertIn("no_direct_execution", decision.restrictions)

    def test_task_idempotency(self):
        a = self.engine.submit_task("m1", "probe", {"x": 1}, idempotency_key="same", now=1000)
        b = self.engine.submit_task("m1", "probe", {"x": 99}, idempotency_key="same", now=1000)
        self.assertEqual(a, b)
        self.assertEqual(len(self.store.list_tasks("m1")), 1)

    def test_priority_and_block_isolation(self):
        low = self.engine.submit_task("m1", "low", {}, idempotency_key="low", priority=1, now=1000)
        high = self.engine.submit_task("m1", "high", {}, idempotency_key="high", priority=10, now=1000)
        lease = self.engine.claim_next("w1", now=1000)
        self.assertEqual(lease.id, high)
        self.engine.block_task(lease, "external dependency", now=1001)
        next_lease = self.engine.claim_next("w2", now=1002)
        self.assertEqual(next_lease.id, low)

    def test_retry_then_failure(self):
        tid = self.engine.submit_task("m1", "fragile", {}, idempotency_key="fragile", max_attempts=2, now=1000)
        lease1 = self.engine.claim_next("w1", now=1000)
        self.assertEqual(lease1.id, tid)
        self.assertEqual(self.engine.fail_task(lease1, "boom1", now=1001), "QUEUED")
        lease2 = self.engine.claim_next("w1", now=1002)
        self.assertEqual(self.engine.fail_task(lease2, "boom2", now=1003), "FAILED")
        self.assertEqual(self.store.get_task(tid)["state"], "FAILED")

    def test_restart_and_expired_lease_recovery(self):
        tid = self.engine.submit_task("m1", "resume", {}, idempotency_key="resume", now=1000)
        lease = self.engine.claim_next("w1", lease_seconds=5, now=1000)
        self.assertEqual(lease.id, tid)
        self.store.close()

        self.store = SQLiteStateStore(self.db)
        self.audit = AuditLedger(self.store)
        self.engine = DurableLoopEngine(self.store, self.audit)
        summary = self.engine.resume(now=1006)
        self.assertEqual(summary["recovered_leases"], 1)
        lease2 = self.engine.claim_next("w2", now=1006)
        self.assertEqual(lease2.id, tid)
        self.assertEqual(lease2.attempts, 2)

    def test_invalid_mission_transition_and_completion_gate(self):
        with self.assertRaises(StateError):
            self.engine.transition_mission("m1", "COMPLETED", "skip")
        self.engine.transition_mission("m1", "AUTHORIZED", "authorized")
        self.engine.transition_mission("m1", "RUNNING", "started")
        self.engine.transition_mission("m1", "VALIDATING", "validate")
        with self.assertRaises(StateError):
            self.engine.transition_mission("m1", "COMPLETED", "not proven")
        self.engine.transition_mission("m1", "COMPLETED", "proven", mission_proven=True)
        self.assertEqual(self.store.get_mission("m1")["state"], "COMPLETED")

    def test_audit_chain_and_tamper_detection(self):
        self.audit.append(actor="a", action="one", payload={"x": 1})
        self.audit.append(actor="b", action="two", payload={"x": 2})
        self.assertEqual(self.audit.verify_chain(), (True, None))
        self.store.conn.execute("UPDATE audit_events SET payload_json='{}' WHERE seq=2")
        ok, bad_seq = self.audit.verify_chain()
        self.assertFalse(ok)
        self.assertEqual(bad_seq, 2)

    def test_mission_proof_engine(self):
        proof_engine = MissionProofEngine(self.audit)
        partial = proof_engine.evaluate("m1", {"scope_explicit": True})
        self.assertFalse(partial.proven)
        full = proof_engine.evaluate("m1", {k: True for k in REQUIRED_GATES})
        self.assertTrue(full.proven)
        self.assertEqual(full.missing_gates, ())


if __name__ == "__main__":
    unittest.main()
