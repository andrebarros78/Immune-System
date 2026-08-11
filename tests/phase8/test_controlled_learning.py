from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path

from immune_core.audit import AuditLedger
from immune_core.diagnosis import IncidentEngine
from immune_core.engine import DurableLoopEngine
from immune_core.identity import IdentityAuthority
from immune_core.learning import ControlledLearningEngine, LearningError
from immune_core.observability import ObservabilityStore
from immune_core.remediation import RemediationPlanner
from immune_core.skills import SkillError
from immune_core.storage import SQLiteStateStore


NOW = 2_200_000_000


class FakeSkill:
    authority = "adapter-only"
    executable = False


class FakeSkills:
    def __init__(self, approved: bool):
        self.approved = approved

    def resolve_approved(self, skill_id: str, version: str):
        if not self.approved:
            raise SkillError("not approved")
        return FakeSkill()


class Phase8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SQLiteStateStore(Path(self.tmp.name) / "state.db")
        self.audit = AuditLedger(self.store)
        self.obs = ObservabilityStore(self.store, self.audit)
        self.identities = IdentityAuthority(b"L" * 32)
        self.incidents = IncidentEngine(self.store, self.obs, self.audit)
        self.planner = RemediationPlanner(self.store, self.incidents, self.obs, self.audit)
        self.engine = DurableLoopEngine(self.store, self.audit)
        for mission, system in (("m1", "system-a"), ("m2", "system-b"), ("m3", "system-c")):
            self.engine.create_mission(mission, system)
            self.engine.transition_mission(mission, "AUTHORIZED", "phase8")
            self.engine.transition_mission(mission, "RUNNING", "phase8")
        self.learning = ControlledLearningEngine(self.store, self.identities, self.obs, self.audit)
        self.registrar = self.identities.issue("registrar", "controller", ("knowledge:register",), ttl_seconds=600, now=NOW)
        self.validator = self.identities.issue("validator", "validator", ("knowledge:validate",), ttl_seconds=600, now=NOW)
        self.reviewer = self.identities.issue("reviewer", "validator", ("knowledge:review",), ttl_seconds=600, now=NOW)
        self.promoter = self.identities.issue("promoter", "controller", ("knowledge:promote",), ttl_seconds=600, now=NOW)
        self.retire = self.identities.issue("retirer", "controller", ("knowledge:retire",), ttl_seconds=600, now=NOW)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _seed_correction(self, mission_id: str, *, accepted: bool = True, passed: bool = True, rolled_back: bool = False, description: str = "repair configuration", validation: dict | None = None, suffix: str | None = None) -> tuple[str, str]:
        import json
        suffix = suffix or uuid.uuid4().hex[:8]
        validation = validation or {"expected_files": {"fixed.txt": "good"}}
        incident_id = f"inc-{suffix}"
        hypothesis_id = f"hyp-{suffix}"
        correction_id = f"corr-{suffix}"
        validation_id = f"val-{suffix}"
        ts = NOW + len(suffix)
        signal_ev = self.obs.evidence(kind="incident_signal", payload={"status": "down", "suffix": suffix}, mission_id=mission_id, ts=ts)
        attempt_ev = self.obs.evidence(kind="discriminating_test", payload={"root": "supported", "suffix": suffix}, mission_id=mission_id, ts=ts + 1)
        plan_ev = self.obs.evidence(kind="correction_plan", payload={"description": description, "suffix": suffix}, mission_id=mission_id, ts=ts + 2)
        validation_ev = self.obs.evidence(kind="remediation_validation", payload={"passed": passed, "rolled_back": rolled_back, "suffix": suffix}, mission_id=mission_id, ts=ts + 3)
        self.store.conn.execute("INSERT INTO diag_incidents(id,mission_id,correlation_key,title,state,root_hypothesis_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (incident_id, mission_id, f"corr-{suffix}", "seeded incident", "RESOLVED" if accepted else "INVESTIGATING", hypothesis_id if accepted else None, ts, ts + 4))
        self.store.conn.execute("INSERT INTO diag_hypotheses(id,incident_id,statement,state,confidence,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (hypothesis_id, incident_id, "configuration drift", "ROOT_CAUSE" if accepted else "SUPPORTED", 0.9, ts, ts + 1))
        self.store.conn.execute("INSERT INTO diag_incident_signals(incident_id,signal_id,evidence_id) VALUES(?,?,?)", (incident_id, f"signal-{suffix}", signal_ev.id))
        self.store.conn.execute("INSERT INTO diag_attempts(id,incident_id,hypothesis_id,strategy,test_name,outcome,progress_score,evidence_id,strategy_fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (f"attempt-{suffix}", incident_id, hypothesis_id, "controlled_reproduction", "config-diff", "SUPPORTED", 1.0, attempt_ev.id, f"fp-{suffix}", ts + 1))
        self.store.conn.execute("INSERT INTO diag_corrections(id,incident_id,mission_id,hypothesis_id,description,task_kind,argv_json,risk_json,validation_json,state,task_id,checkpoint_id,plan_evidence_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (correction_id, incident_id, mission_id, hypothesis_id, description, "command", '["python","-c","pass"]', "{}", json.dumps(validation, sort_keys=True), "ACCEPTED" if accepted else ("ROLLED_BACK" if rolled_back else "PLANNED"), f"task-{suffix}", f"cp-{suffix}", plan_ev.id, ts + 2, ts + 4))
        self.store.conn.execute("INSERT INTO diag_validations(id,correction_id,passed,rolled_back,checks_json,evidence_id,created_at) VALUES(?,?,?,?,?,?,?)", (validation_id, correction_id, int(passed), int(rolled_back), "[]", validation_ev.id, ts + 3))
        return correction_id, validation_id

    def _candidate(self, correction_id: str, *, scope: str = "SYSTEM", lineage: str = "config-fix"):
        return self.learning.create_candidate_from_correction(self.registrar, correction_id=correction_id, lineage_key=lineage, kind="memory", content={"procedure": "repair configuration"}, target_scope=scope, now=NOW + 20)

    def _review(self, knowledge_id: str):
        return self.learning.review_integrity(self.reviewer, knowledge_id, now=NOW + 30)

    def _promote(self, knowledge_id: str):
        return self.learning.promote(self.promoter, knowledge_id, now=NOW + 31)

    def test_candidate_starts_quarantined_with_derived_provenance(self):
        correction, _ = self._seed_correction("m1", suffix="a1")
        item = self._candidate(correction)
        self.assertEqual(item.state, "QUARANTINED")
        self.assertGreater(item.confidence, 0.6)
        self.assertEqual(item.provenance["correction_id"], correction)
        self.assertTrue(item.provenance["root_hypothesis_id"])
        self.assertGreaterEqual(len(item.provenance["evidence_ids"]), 4)

    def test_unaccepted_correction_cannot_create_learning(self):
        correction, _ = self._seed_correction("m1", accepted=False, suffix="a2")
        with self.assertRaises(LearningError):
            self._candidate(correction)

    def test_tampered_source_evidence_blocks_learning(self):
        correction, _ = self._seed_correction("m1", suffix="a3")
        row = self.store.conn.execute("SELECT plan_evidence_id FROM diag_corrections WHERE id=?", (correction,)).fetchone()
        self.store.conn.execute("UPDATE obs_evidence SET payload_json='{}' WHERE id=?", (row["plan_evidence_id"],))
        with self.assertRaises(LearningError):
            self._candidate(correction)

    def test_ai_identity_without_scope_cannot_register_or_promote(self):
        correction, _ = self._seed_correction("m1", suffix="a4")
        ai = self.identities.issue("ai-provider", "ai", (), ttl_seconds=600, now=NOW)
        with self.assertRaises(Exception):
            self.learning.create_candidate_from_correction(ai, correction_id=correction, lineage_key="x", kind="memory", content={"x": 1}, now=NOW + 1)
        item = self._candidate(correction)
        self._review(item.id)
        with self.assertRaises(Exception):
            self.learning.promote(ai, item.id, now=NOW + 2)

    def test_promotion_requires_prior_valid_review(self):
        correction, _ = self._seed_correction("m1", suffix="a5")
        item = self._candidate(correction)
        with self.assertRaises(LearningError):
            self._promote(item.id)

    def test_reviewer_and_promoter_must_be_distinct(self):
        correction, _ = self._seed_correction("m1", suffix="a6")
        item = self._candidate(correction)
        same = self.identities.issue("same-person", "controller", ("knowledge:review", "knowledge:promote"), ttl_seconds=600, now=NOW)
        self.learning.review_integrity(same, item.id, now=NOW + 1)
        with self.assertRaises(LearningError):
            self.learning.promote(same, item.id, now=NOW + 2)

    def test_system_knowledge_promotes_after_one_proven_success(self):
        correction, _ = self._seed_correction("m1", suffix="a7")
        item = self._candidate(correction)
        self._review(item.id)
        promoted = self._promote(item.id)
        self.assertEqual(promoted.state, "PROMOTED")
        self.assertEqual([x.id for x in self.learning.recall_promoted(system_id="system-a")], [item.id])
        self.assertEqual(self.learning.recall_promoted(system_id="system-b"), [])

    def test_global_knowledge_requires_two_distinct_systems(self):
        first, _ = self._seed_correction("m1", suffix="a8")
        item = self._candidate(first, scope="GLOBAL")
        self._review(item.id)
        with self.assertRaises(LearningError):
            self._promote(item.id)
        second, _ = self._seed_correction("m2", suffix="a9")
        self.learning.add_reproduction_from_correction(self.validator, item.id, second, now=NOW + 25)
        self._review(item.id)
        promoted = self._promote(item.id)
        self.assertEqual(promoted.state, "PROMOTED")
        self.assertGreaterEqual(promoted.confidence, 0.70)
        self.assertEqual([x.id for x in self.learning.recall_promoted(system_id="system-c")], [item.id])

    def test_mismatched_remediation_cannot_be_called_reproduction(self):
        first, _ = self._seed_correction("m1", suffix="b1")
        item = self._candidate(first, scope="GLOBAL")
        other, _ = self._seed_correction("m2", description="replace network route", suffix="b2")
        with self.assertRaises(LearningError):
            self.learning.add_reproduction_from_correction(self.validator, item.id, other, now=NOW + 1)

    def test_duplicate_reproduction_is_rejected(self):
        first, _ = self._seed_correction("m1", suffix="b3")
        item = self._candidate(first)
        with self.assertRaises(LearningError):
            self.learning.add_reproduction_from_correction(self.validator, item.id, first, now=NOW + 1)

    def test_regression_reduces_confidence_and_suspends_promoted_knowledge(self):
        first, _ = self._seed_correction("m1", suffix="b4")
        item = self._candidate(first)
        self._review(item.id)
        promoted = self._promote(item.id)
        _, bad_val = self._seed_correction("m2", accepted=False, passed=False, rolled_back=True, suffix="b5")
        after = self.learning.record_regression_from_validation(self.reviewer, item.id, bad_val, now=NOW + 50)
        self.assertEqual(after.state, "SUSPENDED")
        self.assertLess(after.confidence, promoted.confidence)
        self.assertEqual(self.learning.recall_promoted(system_id="system-a"), [])

    def test_two_independent_regressions_retire_knowledge(self):
        first, _ = self._seed_correction("m1", suffix="b6")
        item = self._candidate(first)
        self._review(item.id)
        self._promote(item.id)
        _, bad1 = self._seed_correction("m2", accepted=False, passed=False, rolled_back=True, suffix="b7")
        self.learning.record_regression_from_validation(self.reviewer, item.id, bad1, now=NOW + 50)
        _, bad2 = self._seed_correction("m3", accepted=False, passed=False, rolled_back=True, suffix="b8")
        retired = self.learning.record_regression_from_validation(self.reviewer, item.id, bad2, now=NOW + 51)
        self.assertEqual(retired.state, "RETIRED")

    def test_integrity_review_suspends_tampered_promoted_knowledge(self):
        first, _ = self._seed_correction("m1", suffix="b9")
        item = self._candidate(first)
        self._review(item.id)
        self._promote(item.id)
        evidence_id = item.provenance["evidence_ids"][0]
        self.store.conn.execute("UPDATE obs_evidence SET payload_json='{}' WHERE id=?", (evidence_id,))
        reviewed = self.learning.review_integrity(self.reviewer, item.id, now=NOW + 80)
        self.assertEqual(reviewed.state, "SUSPENDED")

    def test_manual_retirement_requires_authority_and_reason(self):
        first, _ = self._seed_correction("m1", suffix="c1")
        item = self._candidate(first)
        no_scope = self.identities.issue("x", "human", (), ttl_seconds=600, now=NOW)
        with self.assertRaises(Exception):
            self.learning.retire(no_scope, item.id, reason="bad", now=NOW + 1)
        with self.assertRaises(LearningError):
            self.learning.retire(self.retire, item.id, reason="", now=NOW + 1)
        retired = self.learning.retire(self.retire, item.id, reason="manual evidence review", now=NOW + 2)
        self.assertEqual(retired.state, "RETIRED")

    def test_new_version_can_supersede_equal_or_better_knowledge(self):
        c1, _ = self._seed_correction("m1", suffix="c2")
        v1 = self._candidate(c1, lineage="lineage")
        self._review(v1.id)
        self._promote(v1.id)
        c2, _ = self._seed_correction("m2", suffix="c3")
        v2 = self._candidate(c2, lineage="lineage")
        self._review(v2.id)
        promoted = self._promote(v2.id)
        self.assertEqual(promoted.version, 2)
        self.assertEqual(promoted.supersedes_id, v1.id)
        self.assertEqual(self.learning.get(v1.id).state, "SUPERSEDED")

    def test_lower_confidence_version_cannot_supersede_stronger_global_knowledge(self):
        c1, _ = self._seed_correction("m1", suffix="c4")
        strong = self._candidate(c1, scope="GLOBAL", lineage="strong-lineage")
        c2, _ = self._seed_correction("m2", suffix="c5")
        self.learning.add_reproduction_from_correction(self.validator, strong.id, c2, now=NOW + 1)
        self._review(strong.id)
        self._promote(strong.id)
        c3, _ = self._seed_correction("m3", suffix="c6")
        weak = self._candidate(c3, scope="SYSTEM", lineage="strong-lineage")
        self._review(weak.id)
        with self.assertRaises(LearningError):
            self._promote(weak.id)

    def test_skill_learning_never_auto_approves_skill(self):
        correction, _ = self._seed_correction("m1", suffix="c7")
        blocked_engine = ControlledLearningEngine(self.store, self.identities, self.obs, self.audit, skills=FakeSkills(False))
        with self.assertRaises(LearningError):
            blocked_engine.create_candidate_from_correction(self.registrar, correction_id=correction, lineage_key="skill-x", kind="skill", content={"skill": "x"}, skill_id="x", skill_version="1", now=NOW + 1)
        allowed_engine = ControlledLearningEngine(self.store, self.identities, self.obs, self.audit, skills=FakeSkills(True))
        item = allowed_engine.create_candidate_from_correction(self.registrar, correction_id=correction, lineage_key="skill-x", kind="skill", content={"skill": "x"}, skill_id="x", skill_version="1", now=NOW + 2)
        self.assertEqual(item.state, "QUARANTINED")

    def test_provenance_and_reviews_are_auditable(self):
        correction, _ = self._seed_correction("m1", suffix="c8")
        item = self._candidate(correction)
        self._review(item.id)
        data = self.learning.provenance(item.id)
        self.assertEqual(data["knowledge"]["id"], item.id)
        self.assertEqual(len(data["outcomes"]), 1)
        self.assertEqual(data["reviews"][-1]["verdict"], "VALID")
        valid, bad_seq = self.audit.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(bad_seq)


if __name__ == "__main__":
    unittest.main()
