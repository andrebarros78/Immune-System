from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .audit import AuditLedger
from .observability import ObservabilityStore
from .storage import SQLiteStateStore


class DiagnosisError(RuntimeError):
    pass


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class IncidentRef:
    id: str
    mission_id: str
    correlation_key: str
    state: str
    root_hypothesis_id: str | None


@dataclass(frozen=True)
class HypothesisRef:
    id: str
    incident_id: str
    statement: str
    state: str
    confidence: float


@dataclass(frozen=True)
class AttemptRef:
    id: str
    incident_id: str
    hypothesis_id: str
    strategy: str
    test_name: str
    outcome: str
    progress_score: float
    evidence_id: str


class IncidentEngine:
    """Durable incident, hypothesis and attempt state with evidence-backed causal gates."""

    ACTIVE_INCIDENT_STATES = {"OPEN", "INVESTIGATING", "ROOT_CAUSE_CONFIRMED", "REMEDIATING", "VALIDATING", "BLOCKED"}

    def __init__(self, store: SQLiteStateStore, observability: ObservabilityStore, audit: AuditLedger):
        self.store = store
        self.observability = observability
        self.audit = audit
        self._init_schema()

    def _init_schema(self) -> None:
        self.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS diag_incidents(
                id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL,
                correlation_key TEXT NOT NULL,
                title TEXT NOT NULL,
                state TEXT NOT NULL,
                root_hypothesis_id TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_diag_incident_corr ON diag_incidents(mission_id, correlation_key, state);
            CREATE TABLE IF NOT EXISTS diag_incident_signals(
                incident_id TEXT NOT NULL,
                signal_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                PRIMARY KEY(incident_id, signal_id)
            );
            CREATE TABLE IF NOT EXISTS diag_hypotheses(
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                statement TEXT NOT NULL,
                state TEXT NOT NULL,
                confidence REAL NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_diag_hyp_incident ON diag_hypotheses(incident_id, state);
            CREATE TABLE IF NOT EXISTS diag_hypothesis_evidence(
                hypothesis_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                polarity TEXT NOT NULL,
                weight REAL NOT NULL,
                kind TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY(hypothesis_id, evidence_id, polarity)
            );
            CREATE TABLE IF NOT EXISTS diag_attempts(
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                hypothesis_id TEXT NOT NULL,
                strategy TEXT NOT NULL,
                test_name TEXT NOT NULL,
                outcome TEXT NOT NULL,
                progress_score REAL NOT NULL,
                evidence_id TEXT NOT NULL,
                strategy_fingerprint TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_diag_attempts_incident ON diag_attempts(incident_id, created_at);
            """
        )

    def _incident(self, incident_id: str) -> dict[str, Any]:
        row = self.store.conn.execute("SELECT * FROM diag_incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise DiagnosisError("incident not found")
        return dict(row)

    def incident(self, incident_id: str) -> IncidentRef:
        row = self._incident(incident_id)
        return IncidentRef(str(row["id"]), str(row["mission_id"]), str(row["correlation_key"]), str(row["state"]), row["root_hypothesis_id"])

    def create_or_attach_from_signal(self, signal_id: str, mission_id: str, *, title: str | None = None, now: float | None = None) -> IncidentRef:
        signal = self.store.conn.execute("SELECT * FROM obs_signals WHERE id=?", (signal_id,)).fetchone()
        if signal is None:
            raise DiagnosisError("signal not found")
        when = time.time() if now is None else float(now)
        correlation_key = str(signal["correlation_key"])
        existing = self.store.conn.execute(
            "SELECT * FROM diag_incidents WHERE mission_id=? AND correlation_key=? AND state!='RESOLVED' ORDER BY created_at LIMIT 1",
            (mission_id, correlation_key),
        ).fetchone()
        if existing is None:
            incident_id = str(uuid.uuid4())
            self.store.conn.execute(
                "INSERT INTO diag_incidents(id,mission_id,correlation_key,title,state,root_hypothesis_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (incident_id, mission_id, correlation_key, title or f"Incident {correlation_key}", "OPEN", None, when, when),
            )
        else:
            incident_id = str(existing["id"])
            self.store.conn.execute("UPDATE diag_incidents SET updated_at=? WHERE id=?", (when, incident_id))
        payload = {
            "signal_id": signal_id,
            "sensor_id": str(signal["sensor_id"]),
            "kind": str(signal["kind"]),
            "subject": str(signal["subject"]),
            "severity": str(signal["severity"]),
            "fingerprint": str(signal["fingerprint"]),
            "raw_sha256": str(signal["raw_sha256"]),
        }
        evidence = self.observability.evidence(kind="incident_signal", payload=payload, mission_id=mission_id, ts=when)
        self.store.conn.execute(
            "INSERT OR IGNORE INTO diag_incident_signals(incident_id,signal_id,evidence_id) VALUES(?,?,?)",
            (incident_id, signal_id, evidence.id),
        )
        self.store.conn.execute("UPDATE diag_incidents SET state='INVESTIGATING', updated_at=? WHERE id=? AND state='OPEN'", (when, incident_id))
        self.audit.append(actor="diagnosis-engine", action="incident_signal_attached", mission_id=mission_id, payload={"incident_id": incident_id, "signal_id": signal_id, "evidence_id": evidence.id}, now=when)
        return self.incident(incident_id)

    def add_hypothesis(self, incident_id: str, statement: str, *, confidence: float = 0.5, now: float | None = None) -> HypothesisRef:
        if not statement.strip():
            raise DiagnosisError("hypothesis statement is required")
        incident = self._incident(incident_id)
        if incident["state"] == "RESOLVED":
            raise DiagnosisError("resolved incident cannot accept new hypotheses")
        when = time.time() if now is None else float(now)
        hypothesis_id = str(uuid.uuid4())
        score = max(0.0, min(1.0, float(confidence)))
        self.store.conn.execute(
            "INSERT INTO diag_hypotheses(id,incident_id,statement,state,confidence,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (hypothesis_id, incident_id, statement.strip(), "ACTIVE", score, when, when),
        )
        self.audit.append(actor="diagnosis-engine", action="hypothesis_created", mission_id=str(incident["mission_id"]), payload={"incident_id": incident_id, "hypothesis_id": hypothesis_id}, now=when)
        return HypothesisRef(hypothesis_id, incident_id, statement.strip(), "ACTIVE", score)

    def hypothesis(self, hypothesis_id: str) -> HypothesisRef:
        row = self.store.conn.execute("SELECT * FROM diag_hypotheses WHERE id=?", (hypothesis_id,)).fetchone()
        if row is None:
            raise DiagnosisError("hypothesis not found")
        return HypothesisRef(str(row["id"]), str(row["incident_id"]), str(row["statement"]), str(row["state"]), float(row["confidence"]))

    def link_evidence(self, hypothesis_id: str, evidence_id: str, *, polarity: str, weight: float = 1.0, kind: str = "observation", now: float | None = None) -> HypothesisRef:
        hypothesis = self.hypothesis(hypothesis_id)
        if polarity not in {"support", "refute"}:
            raise DiagnosisError("polarity must be support or refute")
        if weight <= 0:
            raise DiagnosisError("evidence weight must be positive")
        if not self.observability.verify_evidence(evidence_id):
            raise DiagnosisError("evidence integrity verification failed")
        when = time.time() if now is None else float(now)
        self.store.conn.execute(
            "INSERT OR REPLACE INTO diag_hypothesis_evidence(hypothesis_id,evidence_id,polarity,weight,kind,created_at) VALUES(?,?,?,?,?,?)",
            (hypothesis_id, evidence_id, polarity, float(weight), kind, when),
        )
        support, refute = self._evidence_weights(hypothesis_id)
        confidence = max(0.0, min(1.0, 0.5 + 0.12 * (support - refute)))
        state = "SUPPORTED" if support > refute else ("REFUTED" if refute > support else "ACTIVE")
        self.store.conn.execute("UPDATE diag_hypotheses SET confidence=?, state=?, updated_at=? WHERE id=?", (confidence, state, when, hypothesis_id))
        incident = self._incident(hypothesis.incident_id)
        self.audit.append(actor="diagnosis-engine", action="hypothesis_evidence_linked", mission_id=str(incident["mission_id"]), payload={"incident_id": hypothesis.incident_id, "hypothesis_id": hypothesis_id, "evidence_id": evidence_id, "polarity": polarity, "kind": kind}, now=when)
        return self.hypothesis(hypothesis_id)

    def _evidence_weights(self, hypothesis_id: str) -> tuple[float, float]:
        rows = self.store.conn.execute("SELECT polarity,weight FROM diag_hypothesis_evidence WHERE hypothesis_id=?", (hypothesis_id,)).fetchall()
        support = sum(float(row["weight"]) for row in rows if row["polarity"] == "support")
        refute = sum(float(row["weight"]) for row in rows if row["polarity"] == "refute")
        return support, refute

    def record_attempt(self, incident_id: str, hypothesis_id: str, *, strategy: str, test_name: str, outcome: str, progress_score: float, evidence_id: str, now: float | None = None) -> AttemptRef:
        hypothesis = self.hypothesis(hypothesis_id)
        if hypothesis.incident_id != incident_id:
            raise DiagnosisError("hypothesis does not belong to incident")
        if not strategy.strip() or not test_name.strip():
            raise DiagnosisError("strategy and test name are required")
        if not self.observability.verify_evidence(evidence_id):
            raise DiagnosisError("attempt evidence integrity verification failed")
        when = time.time() if now is None else float(now)
        attempt_id = str(uuid.uuid4())
        fingerprint = _digest({"strategy": strategy.strip(), "test_name": test_name.strip()})
        normalized_outcome = outcome.strip().upper()
        self.store.conn.execute(
            "INSERT INTO diag_attempts(id,incident_id,hypothesis_id,strategy,test_name,outcome,progress_score,evidence_id,strategy_fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (attempt_id, incident_id, hypothesis_id, strategy.strip(), test_name.strip(), normalized_outcome, float(progress_score), evidence_id, fingerprint, when),
        )
        incident = self._incident(incident_id)
        self.audit.append(actor="diagnosis-engine", action="diagnostic_attempt_recorded", mission_id=str(incident["mission_id"]), payload={"incident_id": incident_id, "hypothesis_id": hypothesis_id, "attempt_id": attempt_id, "strategy": strategy, "test_name": test_name, "outcome": normalized_outcome, "progress_score": float(progress_score), "evidence_id": evidence_id}, now=when)
        return AttemptRef(attempt_id, incident_id, hypothesis_id, strategy.strip(), test_name.strip(), normalized_outcome, float(progress_score), evidence_id)

    def rank_hypotheses(self, incident_id: str) -> list[HypothesisRef]:
        rows = self.store.conn.execute("SELECT * FROM diag_hypotheses WHERE incident_id=? ORDER BY confidence DESC, created_at ASC", (incident_id,)).fetchall()
        return [HypothesisRef(str(row["id"]), incident_id, str(row["statement"]), str(row["state"]), float(row["confidence"])) for row in rows]

    def confirm_root_cause(self, incident_id: str, hypothesis_id: str, *, now: float | None = None) -> HypothesisRef:
        incident = self._incident(incident_id)
        hypothesis = self.hypothesis(hypothesis_id)
        if hypothesis.incident_id != incident_id:
            raise DiagnosisError("hypothesis does not belong to incident")
        support, refute = self._evidence_weights(hypothesis_id)
        if support <= 0 or support <= refute:
            raise DiagnosisError("root cause requires net supporting evidence")
        positive_test = self.store.conn.execute(
            "SELECT 1 FROM diag_attempts WHERE incident_id=? AND hypothesis_id=? AND outcome IN ('SUPPORTED','CONFIRMED') AND progress_score>0 LIMIT 1",
            (incident_id, hypothesis_id),
        ).fetchone()
        if positive_test is None:
            raise DiagnosisError("root cause requires a positive discriminating test")
        alternatives = self.store.conn.execute("SELECT id FROM diag_hypotheses WHERE incident_id=? AND id<>?", (incident_id, hypothesis_id)).fetchall()
        for row in alternatives:
            alternative_id = str(row["id"])
            alt_support, alt_refute = self._evidence_weights(alternative_id)
            refuted_test = self.store.conn.execute(
                "SELECT 1 FROM diag_attempts WHERE incident_id=? AND hypothesis_id=? AND outcome='REFUTED' LIMIT 1",
                (incident_id, alternative_id),
            ).fetchone()
            if alt_refute <= alt_support and refuted_test is None:
                raise DiagnosisError("competing hypothesis has not been discriminated")
        when = time.time() if now is None else float(now)
        self.store.conn.execute("UPDATE diag_hypotheses SET state='ROOT_CAUSE', confidence=1.0, updated_at=? WHERE id=?", (when, hypothesis_id))
        self.store.conn.execute("UPDATE diag_incidents SET state='ROOT_CAUSE_CONFIRMED', root_hypothesis_id=?, updated_at=? WHERE id=?", (hypothesis_id, when, incident_id))
        self.audit.append(actor="diagnosis-engine", action="root_cause_confirmed", mission_id=str(incident["mission_id"]), payload={"incident_id": incident_id, "hypothesis_id": hypothesis_id}, now=when)
        return self.hypothesis(hypothesis_id)

    def set_incident_state(self, incident_id: str, state: str, *, now: float | None = None) -> IncidentRef:
        if state not in self.ACTIVE_INCIDENT_STATES | {"RESOLVED"}:
            raise DiagnosisError("invalid incident state")
        incident = self._incident(incident_id)
        when = time.time() if now is None else float(now)
        self.store.conn.execute("UPDATE diag_incidents SET state=?, updated_at=? WHERE id=?", (state, when, incident_id))
        self.audit.append(actor="diagnosis-engine", action="incident_state_changed", mission_id=str(incident["mission_id"]), payload={"incident_id": incident_id, "from": incident["state"], "to": state}, now=when)
        return self.incident(incident_id)

    def resolve_incident(self, incident_id: str, *, validation_evidence_id: str, recovery_verified: bool, regression_verified: bool, now: float | None = None) -> IncidentRef:
        incident = self._incident(incident_id)
        if incident["state"] != "VALIDATING" or not incident["root_hypothesis_id"]:
            raise DiagnosisError("incident must be validating with confirmed root cause")
        if not recovery_verified or not regression_verified:
            raise DiagnosisError("recovery and regression validation are mandatory")
        if not self.observability.verify_evidence(validation_evidence_id):
            raise DiagnosisError("validation evidence integrity verification failed")
        return self.set_incident_state(incident_id, "RESOLVED", now=now)


class ProgressDetector:
    """Detects repeated no-progress attempts and requires a different strategy."""

    def __init__(self, store: SQLiteStateStore, *, repeat_threshold: int = 3):
        if repeat_threshold < 2:
            raise ValueError("repeat_threshold must be >= 2")
        self.store = store
        self.repeat_threshold = int(repeat_threshold)

    def status(self, incident_id: str) -> dict[str, Any]:
        rows = self.store.conn.execute(
            "SELECT strategy,test_name,outcome,progress_score,strategy_fingerprint FROM diag_attempts WHERE incident_id=? ORDER BY created_at DESC LIMIT ?",
            (incident_id, self.repeat_threshold),
        ).fetchall()
        if len(rows) < self.repeat_threshold:
            return {"state": "PROGRESSING", "reason": "insufficient repeated attempts"}
        fingerprints = {str(row["strategy_fingerprint"]) for row in rows}
        no_progress = all(float(row["progress_score"]) <= 0.0 for row in rows)
        if len(fingerprints) == 1 and no_progress:
            return {"state": "STALLED", "reason": "same strategy repeated without measurable progress", "fingerprint": next(iter(fingerprints))}
        return {"state": "PROGRESSING", "reason": "strategy or evidence changed"}

    def require_strategy_change(self, incident_id: str, *, strategy: str, test_name: str) -> None:
        status = self.status(incident_id)
        if status["state"] != "STALLED":
            return
        candidate = _digest({"strategy": strategy.strip(), "test_name": test_name.strip()})
        if candidate == status.get("fingerprint"):
            raise DiagnosisError("stalled loop requires a different diagnostic strategy")

    def suggest_strategy(self, incident_id: str) -> str:
        used = {str(row["strategy"]) for row in self.store.conn.execute("SELECT strategy FROM diag_attempts WHERE incident_id=?", (incident_id,)).fetchall()}
        for candidate in ("controlled_reproduction", "counterfactual", "dependency_isolation", "bisection", "configuration_diff", "fault_injection"):
            if candidate not in used:
                return candidate
        return "independent_reproduction"
