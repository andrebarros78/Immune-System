from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from .audit import AuditLedger
from .engine import DurableLoopEngine
from .identity import IdentityAuthority
from .policy import PolicyGuard
from .storage import SQLiteStateStore


class OperationsError(RuntimeError):
    pass


@dataclass(frozen=True)
class NotificationRef:
    id: str
    kind: str
    severity: str
    subject: str
    state: str
    created_at: float


@dataclass(frozen=True)
class HumanExceptionRef:
    id: str
    mission_id: str
    reason: str
    required_action: str
    consequence: str
    continuation: str
    state: str


@dataclass(frozen=True)
class OperatorCommandRef:
    id: str
    mission_id: str
    action: str
    state: str
    task_id: str | None


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class OperationalStore:
    """Operational UX state only; sovereign mission/incident state remains owned by Core."""

    def __init__(self, store: SQLiteStateStore, audit: AuditLedger):
        self.store = store
        self.audit = audit
        self._init_schema()

    def _init_schema(self) -> None:
        self.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS op_notifications(
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                subject TEXT NOT NULL,
                mission_id TEXT,
                incident_id TEXT,
                payload_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_op_notifications_state ON op_notifications(state, created_at DESC);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_op_notifications_open_fp
              ON op_notifications(fingerprint) WHERE state='OPEN';

            CREATE TABLE IF NOT EXISTS op_human_exceptions(
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                incident_id TEXT,
                reason TEXT NOT NULL,
                required_action TEXT NOT NULL,
                consequence TEXT NOT NULL,
                continuation TEXT NOT NULL,
                state TEXT NOT NULL,
                requested_at REAL NOT NULL,
                decided_at REAL,
                decided_by TEXT,
                decision_note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_op_human_exceptions_state ON op_human_exceptions(state, requested_at DESC);

            CREATE TABLE IF NOT EXISTS op_commands(
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                parameters_json TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                policy_decision TEXT NOT NULL,
                state TEXT NOT NULL,
                task_id TEXT,
                human_exception_id TEXT,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_op_commands_mission ON op_commands(mission_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS op_reports(
                id TEXT PRIMARY KEY,
                report_type TEXT NOT NULL,
                mission_id TEXT,
                incident_id TEXT,
                content_json TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )

    def notify(self, *, kind: str, severity: str, subject: str, payload: dict[str, Any], mission_id: str | None = None, incident_id: str | None = None, now: float | None = None) -> NotificationRef:
        if not kind.strip() or not subject.strip():
            raise OperationsError("notification kind and subject are required")
        when = time.time() if now is None else float(now)
        normalized = severity.strip().upper()
        if normalized not in {"INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise OperationsError("invalid notification severity")
        fingerprint = _sha256({"kind": kind, "subject": subject, "mission_id": mission_id, "incident_id": incident_id})
        existing = self.store.conn.execute("SELECT * FROM op_notifications WHERE fingerprint=? AND state='OPEN'", (fingerprint,)).fetchone()
        if existing is not None:
            self.store.conn.execute("UPDATE op_notifications SET payload_json=?, severity=?, updated_at=? WHERE id=?", (_canonical(payload), normalized, when, existing["id"]))
            return NotificationRef(str(existing["id"]), str(existing["kind"]), normalized, str(existing["subject"]), "OPEN", float(existing["created_at"]))
        nid = str(uuid.uuid4())
        self.store.conn.execute("INSERT INTO op_notifications(id,kind,severity,subject,mission_id,incident_id,payload_json,fingerprint,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (nid, kind.strip(), normalized, subject.strip(), mission_id, incident_id, _canonical(payload), fingerprint, "OPEN", when, when))
        self.audit.append(actor="notification-service", action="notification_opened", mission_id=mission_id, payload={"notification_id": nid, "kind": kind, "severity": normalized, "incident_id": incident_id}, now=when)
        return NotificationRef(nid, kind.strip(), normalized, subject.strip(), "OPEN", when)

    def close_notification(self, notification_id: str, *, now: float | None = None) -> None:
        when = time.time() if now is None else float(now)
        row = self.store.conn.execute("SELECT mission_id,state FROM op_notifications WHERE id=?", (notification_id,)).fetchone()
        if row is None:
            raise OperationsError("notification not found")
        if row["state"] != "OPEN":
            return
        self.store.conn.execute("UPDATE op_notifications SET state='CLOSED',updated_at=? WHERE id=?", (when, notification_id))
        self.audit.append(actor="notification-service", action="notification_closed", mission_id=row["mission_id"], payload={"notification_id": notification_id}, now=when)

    def request_human_exception(self, *, mission_id: str, reason: str, required_action: str, consequence: str, continuation: str, incident_id: str | None = None, now: float | None = None) -> HumanExceptionRef:
        values = [reason, required_action, consequence, continuation]
        if any(not str(x).strip() for x in values):
            raise OperationsError("human exception requires reason, one concrete action, consequence and continuation")
        if "\n" in required_action.strip():
            raise OperationsError("required action must be one concrete action")
        mission = self.store.get_mission(mission_id)
        if mission is None:
            raise OperationsError("mission not found")
        when = time.time() if now is None else float(now)
        xid = str(uuid.uuid4())
        self.store.conn.execute("INSERT INTO op_human_exceptions(id,mission_id,incident_id,reason,required_action,consequence,continuation,state,requested_at) VALUES(?,?,?,?,?,?,?,?,?)", (xid, mission_id, incident_id, reason.strip(), required_action.strip(), consequence.strip(), continuation.strip(), "PENDING", when))
        self.audit.append(actor="human-exception-gate", action="human_exception_requested", mission_id=mission_id, payload={"human_exception_id": xid, "incident_id": incident_id, "required_action": required_action.strip()}, now=when)
        self.notify(kind="WAITING_HUMAN", severity="WARNING", subject=f"Human action required for {mission_id}", payload={"human_exception_id": xid, "required_action": required_action.strip(), "reason": reason.strip()}, mission_id=mission_id, incident_id=incident_id, now=when)
        return HumanExceptionRef(xid, mission_id, reason.strip(), required_action.strip(), consequence.strip(), continuation.strip(), "PENDING")

    def decide_human_exception(self, exception_id: str, token: str, *, approve: bool, note: str = "", now: int | None = None) -> HumanExceptionRef:
        row = self.store.conn.execute("SELECT * FROM op_human_exceptions WHERE id=?", (exception_id,)).fetchone()
        if row is None:
            raise OperationsError("human exception not found")
        if row["state"] != "PENDING":
            raise OperationsError("human exception already decided")
        principal = self._identity.verify(token, required_scope="human:approve", now=now)
        state = "APPROVED" if approve else "REJECTED"
        when = time.time() if now is None else float(now)
        self.store.conn.execute("UPDATE op_human_exceptions SET state=?,decided_at=?,decided_by=?,decision_note=? WHERE id=?", (state, when, principal.subject, note.strip(), exception_id))
        self.audit.append(actor=principal.subject, action="human_exception_decided", mission_id=str(row["mission_id"]), payload={"human_exception_id": exception_id, "decision": state}, now=when)
        return HumanExceptionRef(str(row["id"]), str(row["mission_id"]), str(row["reason"]), str(row["required_action"]), str(row["consequence"]), str(row["continuation"]), state)

    def bind_identity(self, identity: IdentityAuthority) -> "OperationalStore":
        self._identity = identity
        return self


class ReadModel:
    """Pure SELECT projection. It never mutates sovereign or operational state."""

    TERMINAL_TASK_STATES = {"COMPLETED", "FAILED", "BLOCKED"}

    def __init__(self, store: SQLiteStateStore, *, freshness_seconds: float = 120.0):
        self.store = store
        self.freshness_seconds = float(freshness_seconds)

    def _table_exists(self, name: str) -> bool:
        row = self.store.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
        return row is not None

    def missions(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.store.conn.execute("SELECT * FROM missions ORDER BY updated_at DESC,id").fetchall()]

    def incidents(self, mission_id: str | None = None) -> list[dict[str, Any]]:
        if not self._table_exists("diag_incidents"):
            return []
        if mission_id:
            rows = self.store.conn.execute("SELECT * FROM diag_incidents WHERE mission_id=? ORDER BY updated_at DESC", (mission_id,)).fetchall()
        else:
            rows = self.store.conn.execute("SELECT * FROM diag_incidents ORDER BY updated_at DESC").fetchall()
        return [dict(row) for row in rows]

    def tasks(self, mission_id: str | None = None) -> list[dict[str, Any]]:
        if mission_id:
            rows = self.store.conn.execute("SELECT id,mission_id,kind,state,priority,attempts,max_attempts,last_error,created_at,updated_at FROM tasks WHERE mission_id=? ORDER BY created_at DESC", (mission_id,)).fetchall()
        else:
            rows = self.store.conn.execute("SELECT id,mission_id,kind,state,priority,attempts,max_attempts,last_error,created_at,updated_at FROM tasks ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def workers(self) -> list[dict[str, Any]]:
        rows = self.store.conn.execute("SELECT lease_owner AS worker_id,COUNT(*) AS running_tasks,MAX(lease_until) AS lease_until FROM tasks WHERE state='RUNNING' AND lease_owner IS NOT NULL GROUP BY lease_owner ORDER BY lease_owner").fetchall()
        return [dict(row) for row in rows]

    def latest_metrics(self, *, limit: int = 32) -> list[dict[str, Any]]:
        if not self._table_exists("obs_metrics"):
            return []
        rows = self.store.conn.execute("""SELECT m.name,m.subject,m.ts,m.value,m.labels_json FROM obs_metrics m JOIN (SELECT name,subject,MAX(ts) AS max_ts FROM obs_metrics GROUP BY name,subject) x ON m.name=x.name AND m.subject=x.subject AND m.ts=x.max_ts ORDER BY m.name,m.subject LIMIT ?""", (int(limit),)).fetchall()
        return [{"name": row["name"], "subject": row["subject"], "ts": row["ts"], "value": row["value"], "labels": json.loads(row["labels_json"])} for row in rows]

    def notifications(self, *, open_only: bool = False) -> list[dict[str, Any]]:
        if not self._table_exists("op_notifications"):
            return []
        sql = "SELECT id,kind,severity,subject,mission_id,incident_id,state,created_at,updated_at FROM op_notifications"
        if open_only:
            sql += " WHERE state='OPEN'"
        sql += " ORDER BY created_at DESC"
        return [dict(row) for row in self.store.conn.execute(sql).fetchall()]

    def human_exceptions(self, *, pending_only: bool = False) -> list[dict[str, Any]]:
        if not self._table_exists("op_human_exceptions"):
            return []
        sql = "SELECT * FROM op_human_exceptions"
        if pending_only:
            sql += " WHERE state='PENDING'"
        sql += " ORDER BY requested_at DESC"
        return [dict(row) for row in self.store.conn.execute(sql).fetchall()]

    def system_health(self, *, now: float | None = None) -> dict[str, Any]:
        when = time.time() if now is None else float(now)
        if not self._table_exists("obs_sensor_health"):
            return {"state": "UNKNOWN", "reason": "no sensor health evidence", "fresh": False, "sensors": []}
        rows = self.store.conn.execute("SELECT * FROM obs_sensor_health ORDER BY sensor_id").fetchall()
        sensors = [dict(row) for row in rows]
        if not sensors:
            return {"state": "UNKNOWN", "reason": "no sensor health evidence", "fresh": False, "sensors": []}
        stale, failed, degraded = [], [], []
        for sensor in sensors:
            last = sensor.get("last_success")
            if last is None or when - float(last) > self.freshness_seconds:
                stale.append(str(sensor["sensor_id"]))
            if sensor["state"] == "FAILED":
                failed.append(str(sensor["sensor_id"]))
            elif sensor["state"] == "DEGRADED":
                degraded.append(str(sensor["sensor_id"]))
        if failed:
            return {"state": "FAILED", "reason": "sensor failure", "fresh": not stale, "failed": failed, "stale": stale, "sensors": sensors}
        if degraded or stale:
            return {"state": "DEGRADED", "reason": "degraded or stale evidence", "fresh": not stale, "degraded": degraded, "stale": stale, "sensors": sensors}
        return {"state": "HEALTHY", "reason": "all configured sensors healthy with fresh success evidence", "fresh": True, "sensors": sensors}

    def dashboard(self, *, now: float | None = None) -> dict[str, Any]:
        missions = self.missions()
        incidents = self.incidents()
        tasks = self.tasks()
        pending = self.human_exceptions(pending_only=True)
        health = self.system_health(now=now)
        active_incidents = [i for i in incidents if i.get("state") not in {"RESOLVED", "CLOSED_WITH_RISK"}]
        active_tasks = [t for t in tasks if t.get("state") not in self.TERMINAL_TASK_STATES]
        return {"health": health, "missions": missions, "active_incidents": active_incidents, "active_tasks": active_tasks, "workers": self.workers(), "metrics": self.latest_metrics(), "notifications": self.notifications(open_only=True), "pending_human_exceptions": pending, "generated_at": time.time() if now is None else float(now), "truth_rule": "HEALTHY requires current sensor evidence; absence or staleness is never green."}


class CommandGateway:
    """Authenticated operator commands. Material actions are queued into the durable Core, never executed by UI."""

    ACTION_SCOPES = {"diagnose": "operator:diagnose", "rollback": "operator:rollback", "cancel": "operator:cancel", "approve": "operator:approve", "restore": "operator:restore", "runbook": "operator:runbook"}

    def __init__(self, store: SQLiteStateStore, identity: IdentityAuthority, policy: PolicyGuard, engine: DurableLoopEngine, audit: AuditLedger):
        self.store = store
        self.identity = identity
        self.policy = policy
        self.engine = engine
        self.audit = audit

    def submit(self, *, mission_id: str, action: str, operator_token: str, target: str | None = None, parameters: dict[str, Any] | None = None, human_exception_id: str | None = None, now: int | None = None) -> OperatorCommandRef:
        normalized = action.strip().lower()
        scope = self.ACTION_SCOPES.get(normalized)
        if scope is None:
            raise OperationsError("unsupported operator command")
        mission = self.store.get_mission(mission_id)
        if mission is None:
            raise OperationsError("mission not found")
        principal = self.identity.verify(operator_token, required_scope=scope, now=now)
        params = dict(parameters or {})
        if normalized == "approve":
            if not human_exception_id:
                raise OperationsError("approve command requires human exception")
            row = self.store.conn.execute("SELECT state FROM op_human_exceptions WHERE id=? AND mission_id=?", (human_exception_id, mission_id)).fetchone()
            if row is None or row["state"] != "APPROVED":
                raise OperationsError("human exception has not been explicitly approved")
        risk = dict(params.get("risk") or {})
        request = {"mission_id": mission_id, "action": f"operator:{normalized}", "required_scope": scope, "mission_authorized": str(mission["state"]) not in {"CANCELLED", "COMPLETED"}, "system_authorized": True, "scope_ok": True, "material_change": False, "checkpoint_valid": bool(params.get("checkpoint_id")) if normalized in {"rollback", "restore"} else False, "irreversible": bool(risk.get("irreversible", False)), "recovery_verified": bool(risk.get("recovery_verified", normalized in {"rollback", "restore"})), "new_cost": bool(risk.get("new_cost", False)), "purchase": bool(risk.get("purchase", False)), "subscription": bool(risk.get("subscription", False)), "disables_security_control": bool(risk.get("disables_security_control", False))}
        decision = self.policy.evaluate_token(operator_token, request, now=now)
        if not decision.permitted:
            raise OperationsError(f"PolicyGuard: {decision.decision}: {decision.reason}")
        cid = str(uuid.uuid4())
        when = time.time() if now is None else float(now)
        task_payload = {"operator_command_id": cid, "action": normalized, "target": target, "parameters": params, "requested_by": principal.subject, "human_exception_id": human_exception_id}
        task_id = self.engine.submit_task(mission_id, "operator_command", task_payload, idempotency_key=f"operator:{cid}", priority=100 if normalized in {"rollback", "restore", "cancel"} else 10, max_attempts=1, now=when)
        self.store.conn.execute("INSERT INTO op_commands(id,mission_id,action,target,parameters_json,requested_by,policy_decision,state,task_id,human_exception_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (cid, mission_id, normalized, target, _canonical(params), principal.subject, decision.decision, "QUEUED", task_id, human_exception_id, when))
        self.audit.append(actor=principal.subject, action="operator_command_queued", mission_id=mission_id, payload={"operator_command_id": cid, "action": normalized, "target": target, "task_id": task_id, "policy_decision": decision.decision}, now=when)
        return OperatorCommandRef(cid, mission_id, normalized, "QUEUED", task_id)


class OperationalEventRouter:
    """Maps proven Core events to informational notifications; it never changes mission state."""

    def __init__(self, operations: OperationalStore):
        self.operations = operations

    def critical_failure(self, mission_id: str, subject: str, *, incident_id: str | None = None, evidence_id: str | None = None, now: float | None = None) -> NotificationRef:
        return self.operations.notify(kind="CRITICAL_FAILURE", severity="CRITICAL", subject=subject, payload={"evidence_id": evidence_id}, mission_id=mission_id, incident_id=incident_id, now=now)

    def recovery(self, mission_id: str, subject: str, *, incident_id: str | None = None, evidence_id: str | None = None, now: float | None = None) -> NotificationRef:
        return self.operations.notify(kind="RECOVERY", severity="INFO", subject=subject, payload={"evidence_id": evidence_id}, mission_id=mission_id, incident_id=incident_id, now=now)

    def mission_blocked(self, mission_id: str, reason: str, *, incident_id: str | None = None, now: float | None = None) -> NotificationRef:
        return self.operations.notify(kind="MISSION_BLOCKED", severity="ERROR", subject=f"Mission {mission_id} blocked", payload={"reason": reason}, mission_id=mission_id, incident_id=incident_id, now=now)

    def rollback(self, mission_id: str, checkpoint_id: str, *, incident_id: str | None = None, now: float | None = None) -> NotificationRef:
        return self.operations.notify(kind="ROLLBACK", severity="WARNING", subject=f"Rollback for {mission_id}", payload={"checkpoint_id": checkpoint_id}, mission_id=mission_id, incident_id=incident_id, now=now)

    def completion(self, mission_id: str, proof_id: str, *, now: float | None = None) -> NotificationRef:
        return self.operations.notify(kind="MISSION_PROVEN", severity="INFO", subject=f"Mission {mission_id} proven", payload={"proof_id": proof_id}, mission_id=mission_id, now=now)


class ReportBuilder:
    """Traceable operational reports: requirement -> action/test -> evidence."""

    def __init__(self, store: SQLiteStateStore, audit: AuditLedger):
        self.store = store
        self.audit = audit

    def build_incident(self, incident_id: str, *, requirement_ids: Iterable[str] = (), now: float | None = None) -> dict[str, Any]:
        incident = self.store.conn.execute("SELECT * FROM diag_incidents WHERE id=?", (incident_id,)).fetchone()
        if incident is None:
            raise OperationsError("incident not found")
        iid = str(incident_id)
        hypotheses = [dict(r) for r in self.store.conn.execute("SELECT * FROM diag_hypotheses WHERE incident_id=? ORDER BY created_at", (iid,)).fetchall()]
        attempts = [dict(r) for r in self.store.conn.execute("SELECT * FROM diag_attempts WHERE incident_id=? ORDER BY created_at", (iid,)).fetchall()]
        corrections = [dict(r) for r in self.store.conn.execute("SELECT * FROM diag_corrections WHERE incident_id=? ORDER BY created_at", (iid,)).fetchall()]
        validations: list[dict[str, Any]] = []
        for correction in corrections:
            validations.extend(dict(r) for r in self.store.conn.execute("SELECT * FROM diag_validations WHERE correction_id=? ORDER BY created_at", (correction["id"],)).fetchall())
        evidence_ids = {str(a["evidence_id"]) for a in attempts}
        evidence_ids.update(str(c["plan_evidence_id"]) for c in corrections)
        evidence_ids.update(str(v["evidence_id"]) for v in validations)
        evidence = []
        for eid in sorted(evidence_ids):
            row = self.store.conn.execute("SELECT id,mission_id,kind,created_at,payload_sha256 FROM obs_evidence WHERE id=?", (eid,)).fetchone()
            if row is not None:
                evidence.append(dict(row))
        reqs = list(requirement_ids) or ["incident-diagnosis", "remediation-validation"]
        trace = [{"requirement": str(req), "actions": [a["test_name"] for a in attempts] + [c["description"] for c in corrections], "tests": [json.loads(v["checks_json"]) for v in validations], "evidence_ids": sorted(evidence_ids)} for req in reqs]
        content = {"report_type": "incident", "incident": dict(incident), "hypotheses": hypotheses, "attempts": attempts, "corrections": corrections, "validations": validations, "evidence": evidence, "traceability": trace, "generated_at": time.time() if now is None else float(now)}
        rid = str(uuid.uuid4())
        digest = _sha256(content)
        self.store.conn.execute("INSERT INTO op_reports(id,report_type,mission_id,incident_id,content_json,content_sha256,created_at) VALUES(?,?,?,?,?,?,?)", (rid, "incident", incident["mission_id"], iid, _canonical(content), digest, content["generated_at"]))
        self.audit.append(actor="report-builder", action="report_generated", mission_id=str(incident["mission_id"]), payload={"report_id": rid, "incident_id": iid, "sha256": digest}, now=content["generated_at"])
        return {"id": rid, "sha256": digest, "content": content}

    def verify(self, report_id: str) -> bool:
        row = self.store.conn.execute("SELECT content_json,content_sha256 FROM op_reports WHERE id=?", (report_id,)).fetchone()
        if row is None:
            return False
        try:
            content = json.loads(row["content_json"])
        except Exception:
            return False
        return _sha256(content) == row["content_sha256"]
