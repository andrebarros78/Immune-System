from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLedger
from .checkpoints import CheckpointManager, WorkspaceManager
from .diagnosis import DiagnosisError, IncidentEngine
from .engine import DurableLoopEngine
from .observability import ObservabilityStore
from .policy import PolicyGuard
from .storage import SQLiteStateStore


class RemediationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CorrectionCandidate:
    id: str
    incident_id: str
    mission_id: str
    hypothesis_id: str
    description: str
    state: str
    task_id: str | None
    checkpoint_id: str | None


@dataclass(frozen=True)
class ValidationResult:
    correction_id: str
    passed: bool
    rolled_back: bool
    evidence_id: str
    checks: tuple[dict[str, Any], ...]


class RemediationPlanner:
    """Creates correction candidates only from a causally confirmed incident."""

    def __init__(self, store: SQLiteStateStore, incidents: IncidentEngine, observability: ObservabilityStore, audit: AuditLedger):
        self.store = store
        self.incidents = incidents
        self.observability = observability
        self.audit = audit
        self._init_schema()

    def _init_schema(self) -> None:
        self.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS diag_corrections(
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                mission_id TEXT NOT NULL,
                hypothesis_id TEXT NOT NULL,
                description TEXT NOT NULL,
                task_kind TEXT NOT NULL,
                argv_json TEXT NOT NULL,
                risk_json TEXT NOT NULL,
                validation_json TEXT NOT NULL,
                state TEXT NOT NULL,
                task_id TEXT,
                checkpoint_id TEXT,
                plan_evidence_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS diag_validations(
                id TEXT PRIMARY KEY,
                correction_id TEXT NOT NULL,
                passed INTEGER NOT NULL,
                rolled_back INTEGER NOT NULL,
                checks_json TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )

    def _row(self, correction_id: str) -> dict[str, Any]:
        row = self.store.conn.execute("SELECT * FROM diag_corrections WHERE id=?", (correction_id,)).fetchone()
        if row is None:
            raise RemediationError("correction not found")
        return dict(row)

    def get(self, correction_id: str) -> CorrectionCandidate:
        row = self._row(correction_id)
        return CorrectionCandidate(str(row["id"]), str(row["incident_id"]), str(row["mission_id"]), str(row["hypothesis_id"]), str(row["description"]), str(row["state"]), row["task_id"], row["checkpoint_id"])

    def plan(self, incident_id: str, *, description: str, task_kind: str, argv: list[str], validation: dict[str, Any], risk: dict[str, Any] | None = None, now: float | None = None) -> CorrectionCandidate:
        incident = self.incidents.incident(incident_id)
        if incident.state != "ROOT_CAUSE_CONFIRMED" or not incident.root_hypothesis_id:
            raise RemediationError("correction requires a causally confirmed root cause")
        if not description.strip() or not task_kind.strip() or not argv or any(not isinstance(item, str) or not item for item in argv):
            raise RemediationError("correction description, task kind and argv are required")
        if not isinstance(validation, dict) or not validation:
            raise RemediationError("explicit validation rules are required")
        when = time.time() if now is None else float(now)
        correction_id = str(uuid.uuid4())
        risk_payload = dict(risk or {})
        plan_payload = {
            "correction_id": correction_id,
            "incident_id": incident_id,
            "hypothesis_id": incident.root_hypothesis_id,
            "description": description.strip(),
            "task_kind": task_kind.strip(),
            "argv_digest": hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode("utf-8")).hexdigest(),
            "risk": risk_payload,
            "validation": validation,
        }
        evidence = self.observability.evidence(kind="correction_plan", payload=plan_payload, mission_id=incident.mission_id, ts=when)
        self.store.conn.execute(
            "INSERT INTO diag_corrections(id,incident_id,mission_id,hypothesis_id,description,task_kind,argv_json,risk_json,validation_json,state,task_id,checkpoint_id,plan_evidence_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (correction_id, incident_id, incident.mission_id, incident.root_hypothesis_id, description.strip(), task_kind.strip(), json.dumps(argv), json.dumps(risk_payload, sort_keys=True), json.dumps(validation, sort_keys=True), "PLANNED", None, None, evidence.id, when, when),
        )
        self.audit.append(actor="remediation-planner", action="correction_planned", mission_id=incident.mission_id, payload={"incident_id": incident_id, "correction_id": correction_id, "hypothesis_id": incident.root_hypothesis_id, "evidence_id": evidence.id}, now=when)
        return self.get(correction_id)


class CorrectionLab:
    """Queues a correction through PolicyGuard and captures a pre-execution rollback checkpoint."""

    ACTIVE_MISSION_STATES = {"AUTHORIZED", "DISCOVERING", "RUNNING", "DEGRADED", "VALIDATING", "CONTAINED"}

    def __init__(self, store: SQLiteStateStore, planner: RemediationPlanner, incidents: IncidentEngine, engine: DurableLoopEngine, policy: PolicyGuard, workspaces: WorkspaceManager, checkpoints: CheckpointManager, audit: AuditLedger):
        self.store = store
        self.planner = planner
        self.incidents = incidents
        self.engine = engine
        self.policy = policy
        self.workspaces = workspaces
        self.checkpoints = checkpoints
        self.audit = audit

    def queue(self, correction_id: str, controller_token: str, *, now: int | None = None) -> CorrectionCandidate:
        row = self.planner._row(correction_id)
        if row["state"] != "PLANNED":
            raise RemediationError("only planned corrections can enter the lab")
        mission = self.store.get_mission(str(row["mission_id"]))
        if mission is None or str(mission["state"]) not in self.ACTIVE_MISSION_STATES:
            raise RemediationError("mission state does not permit remediation")
        risk = json.loads(row["risk_json"])
        request = {
            "mission_id": row["mission_id"],
            "action": "queue_remediation",
            "required_scope": "remediation:authorize",
            "mission_authorized": True,
            "system_authorized": True,
            "scope_ok": True,
            "material_change": False,
            "checkpoint_valid": False,
            "irreversible": bool(risk.get("irreversible", False)),
            "recovery_verified": bool(risk.get("recovery_verified", not risk.get("irreversible", False))),
            "new_cost": bool(risk.get("new_cost", False)),
            "purchase": bool(risk.get("purchase", False)),
            "subscription": bool(risk.get("subscription", False)),
            "trial_with_billing_risk": bool(risk.get("trial_with_billing_risk", False)),
            "commercial_license": bool(risk.get("commercial_license", False)),
            "disables_security_control": bool(risk.get("disables_security_control", False)),
        }
        decision = self.policy.evaluate_token(controller_token, request, now=now)
        if not decision.permitted:
            raise RemediationError(f"PolicyGuard: {decision.decision}: {decision.reason}")
        argv = json.loads(row["argv_json"])
        task_id = self.engine.submit_task(
            str(row["mission_id"]),
            str(row["task_kind"]),
            {"mode": "safe", "material_change": True, "argv": argv, "correction_id": correction_id},
            idempotency_key=f"remediation:{correction_id}",
            max_attempts=1,
            now=float(now) if now is not None else None,
        )
        workspace = self.workspaces.for_task(str(row["mission_id"]), task_id)
        checkpoint = self.checkpoints.create(workspace, str(row["mission_id"]), task_id, now=float(now) if now is not None else None)
        when = time.time() if now is None else float(now)
        self.store.conn.execute("UPDATE diag_corrections SET state='QUEUED', task_id=?, checkpoint_id=?, updated_at=? WHERE id=?", (task_id, checkpoint.id, when, correction_id))
        self.incidents.set_incident_state(str(row["incident_id"]), "REMEDIATING", now=when)
        self.audit.append(actor="correction-lab", action="correction_queued", mission_id=str(row["mission_id"]), payload={"incident_id": row["incident_id"], "correction_id": correction_id, "task_id": task_id, "checkpoint_id": checkpoint.id, "policy_decision": decision.decision}, now=when)
        return self.planner.get(correction_id)


class ValidationEngine:
    """Validates the material effect and rolls back a successful-but-invalid correction."""

    def __init__(self, store: SQLiteStateStore, planner: RemediationPlanner, incidents: IncidentEngine, observability: ObservabilityStore, workspaces: WorkspaceManager, checkpoints: CheckpointManager, audit: AuditLedger):
        self.store = store
        self.planner = planner
        self.incidents = incidents
        self.observability = observability
        self.workspaces = workspaces
        self.checkpoints = checkpoints
        self.audit = audit

    @staticmethod
    def _safe_target(workspace: Path, relative: str) -> Path:
        target = (workspace / relative).resolve()
        if workspace != target and workspace not in target.parents:
            raise RemediationError("validation path escaped workspace")
        return target

    def validate(self, correction_id: str, *, now: float | None = None) -> ValidationResult:
        row = self.planner._row(correction_id)
        if not row["task_id"] or not row["checkpoint_id"]:
            raise RemediationError("correction has not entered the lab")
        task = self.store.get_task(str(row["task_id"]))
        if task is None:
            raise RemediationError("remediation task not found")
        workspace = self.workspaces.for_task(str(row["mission_id"]), str(row["task_id"]))
        rules = json.loads(row["validation_json"])
        checks: list[dict[str, Any]] = []

        def check(name: str, condition: bool, detail: str = "") -> None:
            checks.append({"name": name, "passed": bool(condition), "detail": detail})

        check("task_completed", task["state"] == "COMPLETED", str(task["state"]))
        for relative, expected in dict(rules.get("expected_files") or {}).items():
            target = self._safe_target(workspace, str(relative))
            exists = target.is_file()
            check(f"file_exists:{relative}", exists)
            if exists:
                actual = target.read_text(encoding="utf-8")
                check(f"file_content:{relative}", actual == str(expected), f"actual_sha256={hashlib.sha256(actual.encode()).hexdigest()}")
        for relative in list(rules.get("absent_files") or []):
            target = self._safe_target(workspace, str(relative))
            check(f"file_absent:{relative}", not target.exists())
        if rules.get("audit_chain_required", True):
            valid, bad_seq = self.audit.verify_chain()
            check("audit_chain_valid", valid and bad_seq is None, str(bad_seq))
        passed = bool(checks) and all(item["passed"] for item in checks)
        rolled_back = False
        checkpoint = self.checkpoints.get(str(row["checkpoint_id"]))
        if not passed:
            self.checkpoints.restore(checkpoint, workspace)
            rolled_back = True
        when = time.time() if now is None else float(now)
        payload = {"correction_id": correction_id, "incident_id": row["incident_id"], "task_id": row["task_id"], "passed": passed, "rolled_back": rolled_back, "checks": checks}
        evidence = self.observability.evidence(kind="remediation_validation", payload=payload, mission_id=str(row["mission_id"]), ts=when)
        validation_id = str(uuid.uuid4())
        self.store.conn.execute("INSERT INTO diag_validations(id,correction_id,passed,rolled_back,checks_json,evidence_id,created_at) VALUES(?,?,?,?,?,?,?)", (validation_id, correction_id, int(passed), int(rolled_back), json.dumps(checks, sort_keys=True), evidence.id, when))
        state = "VALIDATED" if passed else "ROLLED_BACK"
        self.store.conn.execute("UPDATE diag_corrections SET state=?, updated_at=? WHERE id=?", (state, when, correction_id))
        self.incidents.set_incident_state(str(row["incident_id"]), "VALIDATING" if passed else "INVESTIGATING", now=when)
        self.audit.append(actor="validation-engine", action="correction_validated", mission_id=str(row["mission_id"]), payload={"incident_id": row["incident_id"], "correction_id": correction_id, "passed": passed, "rolled_back": rolled_back, "evidence_id": evidence.id}, now=when)
        return ValidationResult(correction_id, passed, rolled_back, evidence.id, tuple(checks))

    def finalize_incident(self, correction_id: str, validation: ValidationResult, *, recovery_verified: bool, regression_verified: bool, now: float | None = None) -> None:
        row = self.planner._row(correction_id)
        if not validation.passed or validation.correction_id != correction_id:
            raise RemediationError("failed validation cannot resolve incident")
        self.incidents.resolve_incident(str(row["incident_id"]), validation_evidence_id=validation.evidence_id, recovery_verified=recovery_verified, regression_verified=regression_verified, now=now)
        when = time.time() if now is None else float(now)
        self.store.conn.execute("UPDATE diag_corrections SET state='ACCEPTED', updated_at=? WHERE id=?", (when, correction_id))
        self.audit.append(actor="validation-engine", action="correction_accepted", mission_id=str(row["mission_id"]), payload={"incident_id": row["incident_id"], "correction_id": correction_id, "validation_evidence_id": validation.evidence_id, "recovery_verified": recovery_verified, "regression_verified": regression_verified}, now=when)
