from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .audit import AuditLedger
from .identity import IdentityAuthority
from .observability import ObservabilityStore
from .skills import SkillRegistry, SkillError
from .storage import SQLiteStateStore


class LearningError(RuntimeError):
    pass


@dataclass(frozen=True)
class KnowledgeRecord:
    id: str
    lineage_key: str
    version: int
    mission_id: str
    system_id: str
    incident_id: str
    correction_id: str
    kind: str
    target_scope: str
    state: str
    confidence: float
    content: dict[str, Any]
    content_sha256: str
    remediation_signature: str
    provenance: dict[str, Any]
    created_at: float
    promoted_at: float | None
    supersedes_id: str | None


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class ControlledLearningEngine:
    """Evidence-derived learning. AI may suggest candidates but cannot promote truth."""

    PROMOTION_THRESHOLDS = {"SYSTEM": 0.60, "GLOBAL": 0.70}

    def __init__(
        self,
        store: SQLiteStateStore,
        identity: IdentityAuthority,
        observability: ObservabilityStore,
        audit: AuditLedger,
        *,
        skills: SkillRegistry | None = None,
    ):
        self.store = store
        self.identity = identity
        self.observability = observability
        self.audit = audit
        self.skills = skills
        self._init_schema()

    def _init_schema(self) -> None:
        self.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS learning_knowledge(
                id TEXT PRIMARY KEY,
                lineage_key TEXT NOT NULL,
                version INTEGER NOT NULL,
                mission_id TEXT NOT NULL,
                system_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                correction_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                target_scope TEXT NOT NULL,
                state TEXT NOT NULL,
                confidence REAL NOT NULL,
                content_json TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                remediation_signature TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                skill_id TEXT,
                skill_version TEXT,
                created_at REAL NOT NULL,
                promoted_at REAL,
                reviewed_at REAL,
                supersedes_id TEXT,
                UNIQUE(lineage_key, version)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_state_kind
                ON learning_knowledge(state, kind, promoted_at);
            CREATE TABLE IF NOT EXISTS learning_outcomes(
                id TEXT PRIMARY KEY,
                knowledge_id TEXT NOT NULL,
                correction_id TEXT NOT NULL,
                validation_id TEXT NOT NULL,
                mission_id TEXT NOT NULL,
                system_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                remediation_signature TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(knowledge_id, correction_id, validation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_learning_outcomes_knowledge
                ON learning_outcomes(knowledge_id, created_at);
            CREATE TABLE IF NOT EXISTS learning_reviews(
                id TEXT PRIMARY KEY,
                knowledge_id TEXT NOT NULL,
                reviewer_subject TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence_before REAL NOT NULL,
                confidence_after REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )

    def _table_exists(self, name: str) -> bool:
        row = self.store.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return row is not None

    def _row_to_record(self, row: Any) -> KnowledgeRecord:
        content = json.loads(row["content_json"])
        digest = _sha256(content)
        if digest != row["content_sha256"]:
            raise LearningError(f"knowledge integrity mismatch: {row['id']}")
        provenance = json.loads(row["provenance_json"])
        return KnowledgeRecord(
            id=str(row["id"]),
            lineage_key=str(row["lineage_key"]),
            version=int(row["version"]),
            mission_id=str(row["mission_id"]),
            system_id=str(row["system_id"]),
            incident_id=str(row["incident_id"]),
            correction_id=str(row["correction_id"]),
            kind=str(row["kind"]),
            target_scope=str(row["target_scope"]),
            state=str(row["state"]),
            confidence=float(row["confidence"]),
            content=content,
            content_sha256=str(row["content_sha256"]),
            remediation_signature=str(row["remediation_signature"]),
            provenance=provenance,
            created_at=float(row["created_at"]),
            promoted_at=float(row["promoted_at"]) if row["promoted_at"] is not None else None,
            supersedes_id=row["supersedes_id"],
        )

    def get(self, knowledge_id: str) -> KnowledgeRecord:
        row = self.store.conn.execute(
            "SELECT * FROM learning_knowledge WHERE id=?", (knowledge_id,)
        ).fetchone()
        if row is None:
            raise LearningError("knowledge not found")
        return self._row_to_record(row)

    def _next_version(self, lineage_key: str) -> int:
        row = self.store.conn.execute(
            "SELECT MAX(version) AS v FROM learning_knowledge WHERE lineage_key=?",
            (lineage_key,),
        ).fetchone()
        return 1 if row["v"] is None else int(row["v"]) + 1

    def _evidence_ok(self, evidence_id: str) -> bool:
        return bool(evidence_id) and self.observability.verify_evidence(evidence_id)

    def _correction_snapshot(self, correction_id: str) -> dict[str, Any]:
        required = ("diag_corrections", "diag_incidents", "diag_validations", "missions")
        if not all(self._table_exists(name) for name in required):
            raise LearningError("diagnosis/remediation schema is not initialized")

        correction = self.store.conn.execute(
            "SELECT * FROM diag_corrections WHERE id=?", (correction_id,)
        ).fetchone()
        if correction is None:
            raise LearningError("correction not found")
        if str(correction["state"]) != "ACCEPTED":
            raise LearningError("learning requires an accepted correction")

        incident = self.store.conn.execute(
            "SELECT * FROM diag_incidents WHERE id=?", (correction["incident_id"],)
        ).fetchone()
        if incident is None or str(incident["state"]) != "RESOLVED" or not incident["root_hypothesis_id"]:
            raise LearningError("learning requires a resolved incident with confirmed root cause")

        validation = self.store.conn.execute(
            "SELECT * FROM diag_validations WHERE correction_id=? ORDER BY created_at DESC LIMIT 1",
            (correction_id,),
        ).fetchone()
        if validation is None or int(validation["passed"]) != 1 or int(validation["rolled_back"]) != 0:
            raise LearningError("learning requires successful semantic validation")

        mission = self.store.conn.execute(
            "SELECT * FROM missions WHERE id=?", (correction["mission_id"],)
        ).fetchone()
        if mission is None:
            raise LearningError("mission not found for correction")

        evidence_ids: set[str] = {
            str(correction["plan_evidence_id"]),
            str(validation["evidence_id"]),
        }
        if self._table_exists("diag_attempts"):
            rows = self.store.conn.execute(
                "SELECT evidence_id FROM diag_attempts WHERE incident_id=?",
                (incident["id"],),
            ).fetchall()
            evidence_ids.update(str(r["evidence_id"]) for r in rows)
        if self._table_exists("diag_incident_signals"):
            rows = self.store.conn.execute(
                "SELECT evidence_id FROM diag_incident_signals WHERE incident_id=?",
                (incident["id"],),
            ).fetchall()
            evidence_ids.update(str(r["evidence_id"]) for r in rows)

        invalid = sorted(eid for eid in evidence_ids if not self._evidence_ok(eid))
        if invalid:
            raise LearningError(f"provenance contains invalid evidence: {invalid}")

        remediation_signature = _sha256(
            {
                "task_kind": str(correction["task_kind"]),
                "description": str(correction["description"]),
                "validation": json.loads(correction["validation_json"]),
            }
        )
        return {
            "correction_id": str(correction["id"]),
            "incident_id": str(incident["id"]),
            "root_hypothesis_id": str(incident["root_hypothesis_id"]),
            "mission_id": str(correction["mission_id"]),
            "system_id": str(mission["system_id"]),
            "validation_id": str(validation["id"]),
            "validation_evidence_id": str(validation["evidence_id"]),
            "plan_evidence_id": str(correction["plan_evidence_id"]),
            "evidence_ids": sorted(evidence_ids),
            "remediation_signature": remediation_signature,
            "task_kind": str(correction["task_kind"]),
            "description": str(correction["description"]),
        }

    def _negative_validation_snapshot(self, validation_id: str) -> dict[str, Any]:
        if not self._table_exists("diag_validations"):
            raise LearningError("validation schema is not initialized")
        validation = self.store.conn.execute(
            "SELECT * FROM diag_validations WHERE id=?", (validation_id,)
        ).fetchone()
        if validation is None:
            raise LearningError("validation not found")
        if int(validation["passed"]) == 1 and int(validation["rolled_back"]) == 0:
            raise LearningError("regression requires a failed or rolled-back validation")
        correction = self.store.conn.execute(
            "SELECT * FROM diag_corrections WHERE id=?", (validation["correction_id"],)
        ).fetchone()
        if correction is None:
            raise LearningError("validation correction not found")
        mission = self.store.conn.execute(
            "SELECT * FROM missions WHERE id=?", (correction["mission_id"],)
        ).fetchone()
        if mission is None:
            raise LearningError("validation mission not found")
        evidence_id = str(validation["evidence_id"])
        if not self._evidence_ok(evidence_id):
            raise LearningError("regression evidence integrity verification failed")
        remediation_signature = _sha256(
            {
                "task_kind": str(correction["task_kind"]),
                "description": str(correction["description"]),
                "validation": json.loads(correction["validation_json"]),
            }
        )
        return {
            "validation_id": str(validation["id"]),
            "correction_id": str(correction["id"]),
            "mission_id": str(correction["mission_id"]),
            "system_id": str(mission["system_id"]),
            "evidence_id": evidence_id,
            "remediation_signature": remediation_signature,
        }

    def _recompute_confidence(self, knowledge_id: str) -> tuple[float, int, int, int]:
        rows = self.store.conn.execute(
            "SELECT outcome,system_id FROM learning_outcomes WHERE knowledge_id=?",
            (knowledge_id,),
        ).fetchall()
        successes = sum(1 for r in rows if r["outcome"] == "SUCCESS")
        failures = sum(1 for r in rows if r["outcome"] == "FAILURE")
        distinct_success_systems = len(
            {str(r["system_id"]) for r in rows if r["outcome"] == "SUCCESS"}
        )
        confidence = (successes + 1.0) / (successes + failures + 2.0)
        self.store.conn.execute(
            "UPDATE learning_knowledge SET confidence=? WHERE id=?",
            (confidence, knowledge_id),
        )
        return confidence, successes, failures, distinct_success_systems

    def _append_outcome(
        self,
        knowledge_id: str,
        *,
        correction_id: str,
        validation_id: str,
        mission_id: str,
        system_id: str,
        outcome: str,
        evidence_id: str,
        remediation_signature: str,
        now: float,
    ) -> None:
        try:
            self.store.conn.execute(
                """
                INSERT INTO learning_outcomes(
                    id,knowledge_id,correction_id,validation_id,mission_id,system_id,
                    outcome,evidence_id,remediation_signature,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    str(uuid.uuid4()),
                    knowledge_id,
                    correction_id,
                    validation_id,
                    mission_id,
                    system_id,
                    outcome,
                    evidence_id,
                    remediation_signature,
                    now,
                ),
            )
        except Exception as exc:
            raise LearningError("outcome already recorded or invalid") from exc

    def create_candidate_from_correction(
        self,
        registrar_token: str,
        *,
        correction_id: str,
        lineage_key: str,
        kind: str,
        content: dict[str, Any],
        target_scope: str = "SYSTEM",
        skill_id: str | None = None,
        skill_version: str | None = None,
        now: int | None = None,
    ) -> KnowledgeRecord:
        principal = self.identity.verify(
            registrar_token, required_scope="knowledge:register", now=now
        )
        if not lineage_key.strip() or not kind.strip() or not isinstance(content, dict):
            raise LearningError("lineage, kind and object content are required")
        scope = target_scope.strip().upper()
        if scope not in self.PROMOTION_THRESHOLDS:
            raise LearningError("target_scope must be SYSTEM or GLOBAL")
        snapshot = self._correction_snapshot(correction_id)

        if kind.strip() == "skill":
            if self.skills is None or not skill_id or not skill_version:
                raise LearningError("skill learning requires an attached SkillRegistry and skill reference")
            try:
                skill = self.skills.resolve_approved(skill_id, skill_version)
            except SkillError as exc:
                raise LearningError("skill must already be laboratory-approved") from exc
            if skill.authority != "adapter-only" or skill.executable:
                raise LearningError("skill authority boundary violated")

        ts = float(time.time() if now is None else now)
        knowledge_id = str(uuid.uuid4())
        version = self._next_version(lineage_key.strip())
        digest = _sha256(content)
        provenance = {
            "source": "accepted_remediation",
            "incident_id": snapshot["incident_id"],
            "root_hypothesis_id": snapshot["root_hypothesis_id"],
            "correction_id": snapshot["correction_id"],
            "validation_id": snapshot["validation_id"],
            "evidence_ids": snapshot["evidence_ids"],
            "system_id": snapshot["system_id"],
        }
        self.store.conn.execute(
            """
            INSERT INTO learning_knowledge(
                id,lineage_key,version,mission_id,system_id,incident_id,correction_id,
                kind,target_scope,state,confidence,content_json,content_sha256,
                remediation_signature,provenance_json,skill_id,skill_version,
                created_at,promoted_at,reviewed_at,supersedes_id
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                knowledge_id,
                lineage_key.strip(),
                version,
                snapshot["mission_id"],
                snapshot["system_id"],
                snapshot["incident_id"],
                snapshot["correction_id"],
                kind.strip(),
                scope,
                "QUARANTINED",
                0.0,
                _canonical(content),
                digest,
                snapshot["remediation_signature"],
                _canonical(provenance),
                skill_id,
                skill_version,
                ts,
                None,
                None,
                None,
            ),
        )
        self._append_outcome(
            knowledge_id,
            correction_id=snapshot["correction_id"],
            validation_id=snapshot["validation_id"],
            mission_id=snapshot["mission_id"],
            system_id=snapshot["system_id"],
            outcome="SUCCESS",
            evidence_id=snapshot["validation_evidence_id"],
            remediation_signature=snapshot["remediation_signature"],
            now=ts,
        )
        confidence, _, _, _ = self._recompute_confidence(knowledge_id)
        self.audit.append(
            actor=principal.subject,
            action="knowledge_quarantined",
            mission_id=snapshot["mission_id"],
            payload={
                "knowledge_id": knowledge_id,
                "lineage_key": lineage_key.strip(),
                "version": version,
                "kind": kind.strip(),
                "target_scope": scope,
                "confidence": confidence,
                "source_correction_id": correction_id,
            },
            now=ts,
        )
        return self.get(knowledge_id)

    def add_reproduction_from_correction(
        self,
        validator_token: str,
        knowledge_id: str,
        correction_id: str,
        *,
        now: int | None = None,
    ) -> KnowledgeRecord:
        principal = self.identity.verify(
            validator_token, required_scope="knowledge:validate", now=now
        )
        record = self.get(knowledge_id)
        if record.state not in {"QUARANTINED", "PROMOTED"}:
            raise LearningError("knowledge is not eligible for reproduction")
        snapshot = self._correction_snapshot(correction_id)
        if snapshot["remediation_signature"] != record.remediation_signature:
            raise LearningError("reproduction does not match remediation signature")
        ts = float(time.time() if now is None else now)
        self._append_outcome(
            knowledge_id,
            correction_id=snapshot["correction_id"],
            validation_id=snapshot["validation_id"],
            mission_id=snapshot["mission_id"],
            system_id=snapshot["system_id"],
            outcome="SUCCESS",
            evidence_id=snapshot["validation_evidence_id"],
            remediation_signature=snapshot["remediation_signature"],
            now=ts,
        )
        confidence, successes, failures, systems = self._recompute_confidence(knowledge_id)
        self.audit.append(
            actor=principal.subject,
            action="knowledge_reproduction_recorded",
            mission_id=snapshot["mission_id"],
            payload={
                "knowledge_id": knowledge_id,
                "correction_id": correction_id,
                "confidence": confidence,
                "successes": successes,
                "failures": failures,
                "distinct_success_systems": systems,
            },
            now=ts,
        )
        return self.get(knowledge_id)

    def record_regression_from_validation(
        self,
        reviewer_token: str,
        knowledge_id: str,
        validation_id: str,
        *,
        now: int | None = None,
    ) -> KnowledgeRecord:
        principal = self.identity.verify(
            reviewer_token, required_scope="knowledge:review", now=now
        )
        record = self.get(knowledge_id)
        if record.state in {"RETIRED", "SUPERSEDED"}:
            raise LearningError("retired/superseded knowledge cannot accept regression")
        snapshot = self._negative_validation_snapshot(validation_id)
        if snapshot["remediation_signature"] != record.remediation_signature:
            raise LearningError("regression does not match remediation signature")
        ts = float(time.time() if now is None else now)
        before = record.confidence
        self._append_outcome(
            knowledge_id,
            correction_id=snapshot["correction_id"],
            validation_id=snapshot["validation_id"],
            mission_id=snapshot["mission_id"],
            system_id=snapshot["system_id"],
            outcome="FAILURE",
            evidence_id=snapshot["evidence_id"],
            remediation_signature=snapshot["remediation_signature"],
            now=ts,
        )
        confidence, successes, failures, _ = self._recompute_confidence(knowledge_id)
        new_state = record.state
        if failures >= 2:
            new_state = "RETIRED"
        elif record.state == "PROMOTED":
            new_state = "SUSPENDED"
        self.store.conn.execute(
            "UPDATE learning_knowledge SET state=?, reviewed_at=? WHERE id=?",
            (new_state, ts, knowledge_id),
        )
        self.store.conn.execute(
            """
            INSERT INTO learning_reviews(
                id,knowledge_id,reviewer_subject,verdict,confidence_before,
                confidence_after,evidence_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                str(uuid.uuid4()),
                knowledge_id,
                principal.subject,
                "REGRESSION",
                before,
                confidence,
                _canonical([snapshot["evidence_id"]]),
                ts,
            ),
        )
        self.audit.append(
            actor=principal.subject,
            action="knowledge_regression_recorded",
            mission_id=snapshot["mission_id"],
            payload={
                "knowledge_id": knowledge_id,
                "validation_id": validation_id,
                "confidence_before": before,
                "confidence_after": confidence,
                "successes": successes,
                "failures": failures,
                "state": new_state,
            },
            now=ts,
        )
        return self.get(knowledge_id)

    def review_integrity(
        self,
        reviewer_token: str,
        knowledge_id: str,
        *,
        now: int | None = None,
    ) -> KnowledgeRecord:
        principal = self.identity.verify(
            reviewer_token, required_scope="knowledge:review", now=now
        )
        record = self.get(knowledge_id)
        evidence_ids = list(record.provenance.get("evidence_ids") or [])
        rows = self.store.conn.execute(
            "SELECT evidence_id FROM learning_outcomes WHERE knowledge_id=?",
            (knowledge_id,),
        ).fetchall()
        evidence_ids.extend(str(r["evidence_id"]) for r in rows)
        bad = sorted({eid for eid in evidence_ids if not self._evidence_ok(eid)})
        ts = float(time.time() if now is None else now)
        before = record.confidence
        confidence, _, failures, _ = self._recompute_confidence(knowledge_id)
        verdict = "VALID" if not bad else "INVALID_EVIDENCE"
        state = record.state
        if bad and state == "PROMOTED":
            state = "SUSPENDED"
        if bad and failures >= 2:
            state = "RETIRED"
        self.store.conn.execute(
            "UPDATE learning_knowledge SET state=?, reviewed_at=? WHERE id=?",
            (state, ts, knowledge_id),
        )
        self.store.conn.execute(
            """
            INSERT INTO learning_reviews(
                id,knowledge_id,reviewer_subject,verdict,confidence_before,
                confidence_after,evidence_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                str(uuid.uuid4()),
                knowledge_id,
                principal.subject,
                verdict,
                before,
                confidence,
                _canonical(evidence_ids),
                ts,
            ),
        )
        self.audit.append(
            actor=principal.subject,
            action="knowledge_reviewed",
            mission_id=record.mission_id,
            payload={
                "knowledge_id": knowledge_id,
                "verdict": verdict,
                "bad_evidence_ids": bad,
                "state": state,
            },
            now=ts,
        )
        return self.get(knowledge_id)

    def promote(
        self,
        approver_token: str,
        knowledge_id: str,
        *,
        now: int | None = None,
    ) -> KnowledgeRecord:
        principal = self.identity.verify(
            approver_token, required_scope="knowledge:promote", now=now
        )
        record = self.get(knowledge_id)
        if record.state != "QUARANTINED":
            raise LearningError("only quarantined knowledge can be promoted")
        review = self.store.conn.execute(
            "SELECT * FROM learning_reviews WHERE knowledge_id=? ORDER BY created_at DESC,id DESC LIMIT 1",
            (knowledge_id,),
        ).fetchone()
        if review is None or str(review["verdict"]) != "VALID":
            raise LearningError("knowledge promotion requires a prior valid review")
        if str(review["reviewer_subject"]) == principal.subject:
            raise LearningError("knowledge reviewer and promoter must be different identities")
        confidence, successes, failures, systems = self._recompute_confidence(knowledge_id)
        if failures:
            raise LearningError("knowledge with regression evidence cannot be promoted")
        threshold = self.PROMOTION_THRESHOLDS[record.target_scope]
        if confidence < threshold:
            raise LearningError("knowledge confidence below promotion threshold")
        if record.target_scope == "SYSTEM":
            if successes < 1:
                raise LearningError("system knowledge requires one proven successful remediation")
        else:
            if successes < 2 or systems < 2:
                raise LearningError("global knowledge requires two successful reproductions on distinct systems")

        row = self.store.conn.execute(
            "SELECT skill_id,skill_version FROM learning_knowledge WHERE id=?",
            (knowledge_id,),
        ).fetchone()
        if record.kind == "skill":
            if self.skills is None or not row["skill_id"] or not row["skill_version"]:
                raise LearningError("skill registry unavailable at promotion")
            skill = self.skills.resolve_approved(str(row["skill_id"]), str(row["skill_version"]))
            if skill.authority != "adapter-only" or skill.executable:
                raise LearningError("skill is no longer eligible")

        prior = self.store.conn.execute(
            """
            SELECT * FROM learning_knowledge
            WHERE lineage_key=? AND state='PROMOTED' AND id<>?
            ORDER BY version DESC LIMIT 1
            """,
            (record.lineage_key, knowledge_id),
        ).fetchone()
        supersedes_id = None
        if prior is not None:
            prior_record = self._row_to_record(prior)
            if record.version <= prior_record.version:
                raise LearningError("new knowledge version must advance lineage")
            if confidence < prior_record.confidence:
                raise LearningError("new knowledge cannot supersede higher-confidence promoted knowledge")
            supersedes_id = prior_record.id

        ts = float(time.time() if now is None else now)
        self.store.conn.execute(
            """
            UPDATE learning_knowledge
            SET state='PROMOTED', confidence=?, promoted_at=?, supersedes_id=?
            WHERE id=?
            """,
            (confidence, ts, supersedes_id, knowledge_id),
        )
        if supersedes_id:
            self.store.conn.execute(
                "UPDATE learning_knowledge SET state='SUPERSEDED', reviewed_at=? WHERE id=?",
                (ts, supersedes_id),
            )
        self.audit.append(
            actor=principal.subject,
            action="knowledge_promoted",
            mission_id=record.mission_id,
            payload={
                "knowledge_id": knowledge_id,
                "lineage_key": record.lineage_key,
                "version": record.version,
                "confidence": confidence,
                "target_scope": record.target_scope,
                "successes": successes,
                "distinct_success_systems": systems,
                "supersedes_id": supersedes_id,
            },
            now=ts,
        )
        return self.get(knowledge_id)

    def retire(
        self,
        operator_token: str,
        knowledge_id: str,
        *,
        reason: str,
        evidence_id: str | None = None,
        now: int | None = None,
    ) -> KnowledgeRecord:
        principal = self.identity.verify(
            operator_token, required_scope="knowledge:retire", now=now
        )
        record = self.get(knowledge_id)
        if record.state not in {"PROMOTED", "SUSPENDED", "QUARANTINED"}:
            raise LearningError("knowledge cannot be retired from current state")
        if not reason.strip():
            raise LearningError("retirement reason is required")
        if evidence_id is not None and not self._evidence_ok(evidence_id):
            raise LearningError("retirement evidence is invalid")
        ts = float(time.time() if now is None else now)
        self.store.conn.execute(
            "UPDATE learning_knowledge SET state='RETIRED', reviewed_at=? WHERE id=?",
            (ts, knowledge_id),
        )
        self.audit.append(
            actor=principal.subject,
            action="knowledge_retired",
            mission_id=record.mission_id,
            payload={
                "knowledge_id": knowledge_id,
                "reason": reason.strip(),
                "evidence_id": evidence_id,
            },
            now=ts,
        )
        return self.get(knowledge_id)

    def recall_promoted(
        self,
        *,
        kind: str | None = None,
        system_id: str | None = None,
        limit: int = 20,
    ) -> list[KnowledgeRecord]:
        if limit < 1 or limit > 200:
            raise LearningError("recall limit outside 1..200")
        clauses = ["state='PROMOTED'"]
        params: list[Any] = []
        if kind:
            clauses.append("kind=?")
            params.append(kind)
        if system_id:
            clauses.append("(target_scope='GLOBAL' OR system_id=?)")
            params.append(system_id)
        sql = (
            "SELECT * FROM learning_knowledge WHERE "
            + " AND ".join(clauses)
            + " ORDER BY promoted_at DESC, version DESC LIMIT ?"
        )
        params.append(limit)
        rows = self.store.conn.execute(sql, tuple(params)).fetchall()
        return [self._row_to_record(row) for row in rows]

    def provenance(self, knowledge_id: str) -> dict[str, Any]:
        record = self.get(knowledge_id)
        outcomes = [
            dict(row)
            for row in self.store.conn.execute(
                "SELECT * FROM learning_outcomes WHERE knowledge_id=? ORDER BY created_at,id",
                (knowledge_id,),
            ).fetchall()
        ]
        reviews = [
            dict(row)
            for row in self.store.conn.execute(
                "SELECT * FROM learning_reviews WHERE knowledge_id=? ORDER BY created_at,id",
                (knowledge_id,),
            ).fetchall()
        ]
        return {
            "knowledge": {
                "id": record.id,
                "lineage_key": record.lineage_key,
                "version": record.version,
                "state": record.state,
                "confidence": record.confidence,
                "content_sha256": record.content_sha256,
                "provenance": record.provenance,
            },
            "outcomes": outcomes,
            "reviews": reviews,
        }
