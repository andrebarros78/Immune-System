from __future__ import annotations

import hashlib
import json
import statistics
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .audit import AuditLedger
from .storage import SQLiteStateStore


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class Signal:
    id: str
    sensor_id: str
    kind: str
    subject: str
    ts: float
    severity: str
    attributes: dict[str, Any]
    fingerprint: str
    correlation_key: str
    raw_sha256: str


@dataclass(frozen=True)
class ProcessedSignal:
    signal: Signal
    duplicate: bool
    correlation_count: int


@dataclass(frozen=True)
class EvidenceRef:
    id: str
    mission_id: str | None
    kind: str
    payload_sha256: str
    created_at: float


class ObservabilityStore:
    """Durable, vendor-neutral observability state over the sovereign SQLite store."""

    def __init__(self, store: SQLiteStateStore, audit: AuditLedger | None = None):
        self.store = store
        self.audit = audit
        self._init_schema()

    def _init_schema(self) -> None:
        c = self.store.conn
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS obs_signals(
                id TEXT PRIMARY KEY,
                sensor_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                ts REAL NOT NULL,
                severity TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                correlation_key TEXT NOT NULL,
                raw_sha256 TEXT NOT NULL,
                duplicate INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_obs_signals_fp_ts ON obs_signals(fingerprint, ts);
            CREATE INDEX IF NOT EXISTS idx_obs_signals_corr_ts ON obs_signals(correlation_key, ts);
            CREATE TABLE IF NOT EXISTS obs_metrics(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                subject TEXT NOT NULL,
                ts REAL NOT NULL,
                value REAL NOT NULL,
                labels_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_obs_metrics_name_subject_ts ON obs_metrics(name, subject, ts);
            CREATE TABLE IF NOT EXISTS obs_logs(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                source TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                fields_json TEXT NOT NULL,
                sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS obs_traces(
                span_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                parent_span_id TEXT,
                name TEXT NOT NULL,
                started_at REAL NOT NULL,
                ended_at REAL,
                status TEXT NOT NULL,
                attributes_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_obs_traces_trace ON obs_traces(trace_id, started_at);
            CREATE TABLE IF NOT EXISTS obs_sensor_health(
                sensor_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                consecutive_failures INTEGER NOT NULL,
                last_success REAL,
                last_failure REAL,
                last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS obs_evidence(
                id TEXT PRIMARY KEY,
                mission_id TEXT,
                kind TEXT NOT NULL,
                created_at REAL NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS obs_resources(
                resource_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS obs_dependencies(
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                relation TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                PRIMARY KEY(src, dst, relation)
            );
            """
        )
        c.commit()

    def record_signal(self, processed: ProcessedSignal) -> None:
        s = processed.signal
        self.store.conn.execute(
            "INSERT OR REPLACE INTO obs_signals(id,sensor_id,kind,subject,ts,severity,attributes_json,fingerprint,correlation_key,raw_sha256,duplicate) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (s.id, s.sensor_id, s.kind, s.subject, s.ts, s.severity, json.dumps(s.attributes, sort_keys=True, ensure_ascii=False), s.fingerprint, s.correlation_key, s.raw_sha256, int(processed.duplicate)),
        )
        self.store.conn.commit()

    def recent_fingerprint_count(self, fingerprint: str, since: float) -> int:
        return int(self.store.conn.execute("SELECT COUNT(*) FROM obs_signals WHERE fingerprint=? AND ts>=?", (fingerprint, float(since))).fetchone()[0])

    def recent_correlation_count(self, key: str, since: float) -> int:
        return int(self.store.conn.execute("SELECT COUNT(*) FROM obs_signals WHERE correlation_key=? AND ts>=? AND duplicate=0", (key, float(since))).fetchone()[0])

    def record_metric(self, name: str, subject: str, value: float, *, labels: dict[str, Any] | None = None, ts: float | None = None) -> None:
        when = time.time() if ts is None else float(ts)
        self.store.conn.execute("INSERT INTO obs_metrics(name,subject,ts,value,labels_json) VALUES(?,?,?,?,?)", (str(name), str(subject), when, float(value), json.dumps(labels or {}, sort_keys=True)))
        self.store.conn.commit()

    def metric_values(self, name: str, subject: str, *, limit: int = 50, before: float | None = None) -> list[float]:
        if before is None:
            rows = self.store.conn.execute("SELECT value FROM obs_metrics WHERE name=? AND subject=? ORDER BY ts DESC LIMIT ?", (name, subject, int(limit))).fetchall()
        else:
            rows = self.store.conn.execute("SELECT value FROM obs_metrics WHERE name=? AND subject=? AND ts<? ORDER BY ts DESC LIMIT ?", (name, subject, float(before), int(limit))).fetchall()
        return [float(row[0]) for row in reversed(rows)]

    def record_log(self, source: str, level: str, message: str, *, fields: dict[str, Any] | None = None, ts: float | None = None) -> str:
        when = time.time() if ts is None else float(ts)
        payload = {"ts": when, "source": str(source), "level": str(level).upper(), "message": str(message), "fields": fields or {}}
        digest = _sha256(payload)
        self.store.conn.execute("INSERT INTO obs_logs(ts,source,level,message,fields_json,sha256) VALUES(?,?,?,?,?,?)", (when, payload["source"], payload["level"], payload["message"], json.dumps(payload["fields"], sort_keys=True), digest))
        self.store.conn.commit()
        return digest

    def start_span(self, name: str, *, trace_id: str | None = None, parent_span_id: str | None = None, attributes: dict[str, Any] | None = None, ts: float | None = None) -> tuple[str, str]:
        trace = trace_id or uuid.uuid4().hex
        span = uuid.uuid4().hex
        when = time.time() if ts is None else float(ts)
        self.store.conn.execute("INSERT INTO obs_traces(span_id,trace_id,parent_span_id,name,started_at,ended_at,status,attributes_json) VALUES(?,?,?,?,?,?,?,?)", (span, trace, parent_span_id, str(name), when, None, "RUNNING", json.dumps(attributes or {}, sort_keys=True)))
        self.store.conn.commit()
        return trace, span

    def end_span(self, span_id: str, *, status: str = "OK", attributes: dict[str, Any] | None = None, ts: float | None = None) -> None:
        when = time.time() if ts is None else float(ts)
        row = self.store.conn.execute("SELECT attributes_json FROM obs_traces WHERE span_id=?", (span_id,)).fetchone()
        if row is None:
            raise KeyError("unknown span")
        merged = json.loads(row[0])
        merged.update(attributes or {})
        self.store.conn.execute("UPDATE obs_traces SET ended_at=?, status=?, attributes_json=? WHERE span_id=?", (when, str(status), json.dumps(merged, sort_keys=True), span_id))
        self.store.conn.commit()

    def update_sensor_health(self, sensor_id: str, *, ok: bool, error: str | None = None, ts: float | None = None) -> None:
        when = time.time() if ts is None else float(ts)
        row = self.store.conn.execute("SELECT consecutive_failures,last_success,last_failure FROM obs_sensor_health WHERE sensor_id=?", (sensor_id,)).fetchone()
        failures = int(row[0]) if row else 0
        last_success = row[1] if row else None
        last_failure = row[2] if row else None
        if ok:
            failures = 0
            last_success = when
            state = "HEALTHY"
            error = None
        else:
            failures += 1
            last_failure = when
            state = "DEGRADED" if failures < 3 else "FAILED"
        self.store.conn.execute("INSERT INTO obs_sensor_health(sensor_id,state,consecutive_failures,last_success,last_failure,last_error) VALUES(?,?,?,?,?,?) ON CONFLICT(sensor_id) DO UPDATE SET state=excluded.state,consecutive_failures=excluded.consecutive_failures,last_success=excluded.last_success,last_failure=excluded.last_failure,last_error=excluded.last_error", (sensor_id, state, failures, last_success, last_failure, error))
        self.store.conn.commit()

    def sensor_health(self, sensor_id: str) -> dict[str, Any] | None:
        row = self.store.conn.execute("SELECT * FROM obs_sensor_health WHERE sensor_id=?", (sensor_id,)).fetchone()
        return dict(row) if row is not None else None

    def evidence(self, *, kind: str, payload: dict[str, Any], mission_id: str | None = None, ts: float | None = None) -> EvidenceRef:
        when = time.time() if ts is None else float(ts)
        eid = str(uuid.uuid4())
        digest = _sha256(payload)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.store.conn.execute("INSERT INTO obs_evidence(id,mission_id,kind,created_at,payload_json,payload_sha256) VALUES(?,?,?,?,?,?)", (eid, mission_id, str(kind), when, encoded, digest))
        self.store.conn.commit()
        if self.audit:
            self.audit.append(actor="observability", action="evidence_recorded", mission_id=mission_id, payload={"evidence_id": eid, "kind": kind, "sha256": digest}, now=when)
        return EvidenceRef(eid, mission_id, str(kind), digest, when)

    def verify_evidence(self, evidence_id: str) -> bool:
        row = self.store.conn.execute("SELECT payload_json,payload_sha256 FROM obs_evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            return False
        try:
            payload = json.loads(row[0])
        except Exception:
            return False
        return hashlib.sha256(_canonical(payload)).hexdigest() == row[1]

    def upsert_resource(self, resource_id: str, kind: str, name: str, attributes: dict[str, Any], *, ts: float) -> None:
        payload = json.dumps(attributes, sort_keys=True, ensure_ascii=False)
        self.store.conn.execute("INSERT INTO obs_resources(resource_id,kind,name,attributes_json,first_seen,last_seen) VALUES(?,?,?,?,?,?) ON CONFLICT(resource_id) DO UPDATE SET kind=excluded.kind,name=excluded.name,attributes_json=excluded.attributes_json,last_seen=excluded.last_seen", (resource_id, kind, name, payload, ts, ts))
        self.store.conn.commit()

    def upsert_dependency(self, src: str, dst: str, relation: str, attributes: dict[str, Any], *, ts: float) -> None:
        payload = json.dumps(attributes, sort_keys=True, ensure_ascii=False)
        self.store.conn.execute("INSERT INTO obs_dependencies(src,dst,relation,attributes_json,first_seen,last_seen) VALUES(?,?,?,?,?,?) ON CONFLICT(src,dst,relation) DO UPDATE SET attributes_json=excluded.attributes_json,last_seen=excluded.last_seen", (src, dst, relation, payload, ts, ts))
        self.store.conn.commit()

    def inventory_snapshot(self) -> dict[str, Any]:
        resources = [{"id": row["resource_id"], "kind": row["kind"], "name": row["name"], "attributes": json.loads(row["attributes_json"])} for row in self.store.conn.execute("SELECT * FROM obs_resources ORDER BY resource_id").fetchall()]
        dependencies = [{"src": row["src"], "dst": row["dst"], "relation": row["relation"], "attributes": json.loads(row["attributes_json"])} for row in self.store.conn.execute("SELECT * FROM obs_dependencies ORDER BY src,dst,relation").fetchall()]
        core = {"resources": resources, "dependencies": dependencies}
        return {**core, "sha256": _sha256(core)}


class SignalProcessor:
    SEVERITIES = {"debug": 10, "info": 20, "warning": 30, "error": 40, "critical": 50}

    def __init__(self, store: ObservabilityStore, *, dedupe_window_seconds: float = 60.0, correlation_window_seconds: float = 300.0):
        self.store = store
        self.dedupe_window_seconds = float(dedupe_window_seconds)
        self.correlation_window_seconds = float(correlation_window_seconds)

    def ingest(self, sensor_id: str, observation: dict[str, Any], *, ts: float | None = None) -> ProcessedSignal:
        when = float(observation.get("ts", time.time() if ts is None else ts))
        kind = str(observation.get("kind", "event")).strip() or "event"
        subject = str(observation.get("subject", sensor_id)).strip() or sensor_id
        severity = str(observation.get("severity", "info")).lower()
        if severity not in self.SEVERITIES:
            severity = "info"
        attributes = dict(observation.get("attributes") or {})
        signature_attributes = {k: v for k, v in attributes.items() if k not in {"value", "ts", "timestamp", "duration_ms"}}
        fingerprint = _sha256({"kind": kind, "subject": subject, "attributes": signature_attributes})
        correlation_key = str(attributes.get("correlation_key") or attributes.get("incident_key") or f"{kind}:{subject}")
        raw_sha = _sha256({"sensor_id": sensor_id, "kind": kind, "subject": subject, "severity": severity, "attributes": attributes})
        duplicate = self.store.recent_fingerprint_count(fingerprint, when - self.dedupe_window_seconds) > 0
        signal = Signal(str(uuid.uuid4()), sensor_id, kind, subject, when, severity, attributes, fingerprint, correlation_key, raw_sha)
        corr_count = self.store.recent_correlation_count(correlation_key, when - self.correlation_window_seconds) + (0 if duplicate else 1)
        processed = ProcessedSignal(signal, duplicate, corr_count)
        self.store.record_signal(processed)
        return processed


class AnomalyDetector:
    """Robust metric anomaly detector using median/MAD over prior observations."""

    def __init__(self, store: ObservabilityStore, *, min_samples: int = 5, threshold: float = 6.0, history_limit: int = 50):
        self.store = store
        self.min_samples = int(min_samples)
        self.threshold = float(threshold)
        self.history_limit = int(history_limit)

    def observe(self, name: str, subject: str, value: float, *, ts: float, labels: dict[str, Any] | None = None) -> dict[str, Any]:
        history = self.store.metric_values(name, subject, limit=self.history_limit, before=ts)
        anomaly = False
        score = 0.0
        baseline = None
        if len(history) >= self.min_samples:
            baseline = statistics.median(history)
            deviations = [abs(v - baseline) for v in history]
            mad = statistics.median(deviations)
            if mad > 0:
                score = abs(float(value) - baseline) / (1.4826 * mad)
                anomaly = score >= self.threshold
            else:
                spread = max(history) - min(history)
                epsilon = max(abs(baseline) * 0.05, spread * 2.0, 1e-9)
                score = abs(float(value) - baseline) / epsilon
                anomaly = abs(float(value) - baseline) > epsilon
        self.store.record_metric(name, subject, value, labels=labels, ts=ts)
        return {"anomaly": anomaly, "score": score, "baseline": baseline, "samples": len(history), "value": float(value)}


class DependencyGraph:
    def __init__(self, store: ObservabilityStore):
        self.store = store

    def add(self, src: str, dst: str, relation: str = "depends_on", *, attributes: dict[str, Any] | None = None, ts: float | None = None) -> None:
        self.store.upsert_dependency(str(src), str(dst), str(relation), attributes or {}, ts=time.time() if ts is None else float(ts))

    def downstream(self, resource_id: str) -> list[str]:
        rows = self.store.store.conn.execute("SELECT src FROM obs_dependencies WHERE dst=? ORDER BY src", (resource_id,)).fetchall()
        return [str(row[0]) for row in rows]

    def upstream(self, resource_id: str) -> list[str]:
        rows = self.store.store.conn.execute("SELECT dst FROM obs_dependencies WHERE src=? ORDER BY dst", (resource_id,)).fetchall()
        return [str(row[0]) for row in rows]
