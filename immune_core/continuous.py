from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .audit import AuditLedger
from .engine import DurableLoopEngine
from .observability import ObservabilityStore
from .state_backup import BackupRef, StateBackupManager
from .storage import SQLiteStateStore


class ContinuousOperationError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeCycle:
    id: str
    started_at: float
    completed_at: float
    state: str
    recovered_leases: int
    probes_ok: int
    probes_failed: int
    backup_id: str | None
    restore_drill_ok: bool | None
    evidence_id: str


class SupervisorLock:
    """Cross-platform single-instance lock with bounded stale recovery."""

    def __init__(self, path: str | Path, *, stale_after_seconds: float = 120.0):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stale_after_seconds = float(stale_after_seconds)
        if self.stale_after_seconds <= 0:
            raise ValueError("stale_after_seconds must be positive")
        self._owned = False
        self._token = uuid.uuid4().hex

    def acquire(self, *, now: float | None = None) -> None:
        when = time.time() if now is None else float(now)
        payload = json.dumps({"pid": os.getpid(), "created_at": when, "token": self._token}, sort_keys=True)
        for _ in range(2):
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                try:
                    os.write(fd, payload.encode("utf-8"))
                finally:
                    os.close(fd)
                self._owned = True
                return
            except FileExistsError:
                try:
                    current = json.loads(self.path.read_text(encoding="utf-8"))
                    created_at = float(current.get("created_at", 0))
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    created_at = 0.0
                if when - created_at <= self.stale_after_seconds:
                    raise ContinuousOperationError("supervisor already active")
                self.path.unlink(missing_ok=True)
        raise ContinuousOperationError("could not acquire supervisor lock")

    def release(self) -> None:
        if not self._owned:
            return
        try:
            current = json.loads(self.path.read_text(encoding="utf-8"))
            if str(current.get("token")) == self._token:
                self.path.unlink(missing_ok=True)
        except (OSError, json.JSONDecodeError):
            pass
        self._owned = False


class ContinuousSupervisor:
    """Continuous coordinator without host-execution authority."""

    STATES = {"STARTING", "RUNNING", "DEGRADED", "FAILED_SAFE", "STOPPED"}

    def __init__(
        self,
        store: SQLiteStateStore,
        engine: DurableLoopEngine,
        observability: ObservabilityStore,
        audit: AuditLedger,
        backups: StateBackupManager,
        *,
        probes: Mapping[str, Callable[[], bool]] | None = None,
        backup_interval_seconds: float = 300.0,
        restore_drill_interval_seconds: float = 900.0,
        backup_retention: int = 5,
    ):
        self.store = store
        self.engine = engine
        self.observability = observability
        self.audit = audit
        self.backups = backups
        self.probes = dict(probes or {})
        self.backup_interval_seconds = float(backup_interval_seconds)
        self.restore_drill_interval_seconds = float(restore_drill_interval_seconds)
        self.backup_retention = int(backup_retention)
        if self.backup_interval_seconds <= 0 or self.restore_drill_interval_seconds <= 0:
            raise ValueError("supervisor intervals must be positive")
        if self.backup_retention < 2:
            raise ValueError("backup_retention must be >= 2")
        self._init_schema()

    def _init_schema(self) -> None:
        self.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runtime_state(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                state TEXT NOT NULL,
                boot_count INTEGER NOT NULL,
                started_at REAL,
                heartbeat_at REAL,
                last_backup_at REAL,
                last_backup_id TEXT,
                last_restore_drill_at REAL,
                last_restore_drill_ok INTEGER,
                last_error TEXT
            );
            INSERT OR IGNORE INTO runtime_state(singleton,state,boot_count)
              VALUES(1,'STOPPED',0);
            CREATE TABLE IF NOT EXISTS runtime_cycles(
                id TEXT PRIMARY KEY,
                started_at REAL NOT NULL,
                completed_at REAL NOT NULL,
                state TEXT NOT NULL,
                recovered_leases INTEGER NOT NULL,
                probes_ok INTEGER NOT NULL,
                probes_failed INTEGER NOT NULL,
                backup_id TEXT,
                restore_drill_ok INTEGER,
                evidence_id TEXT NOT NULL
            );
            """
        )

    def status(self) -> dict:
        row = self.store.conn.execute("SELECT * FROM runtime_state WHERE singleton=1").fetchone()
        if row is None:
            raise ContinuousOperationError("runtime state disappeared")
        return dict(row)

    def _update_state(
        self,
        state: str,
        *,
        now: float,
        error: str | None = None,
        backup: BackupRef | None = None,
        restore_drill: bool | None = None,
    ) -> None:
        if state not in self.STATES:
            raise ValueError("invalid runtime state")
        fields = ["state=?", "heartbeat_at=?", "last_error=?"]
        values: list[object] = [state, now, error]
        if backup is not None:
            fields.extend(["last_backup_at=?", "last_backup_id=?"])
            values.extend([backup.created_at, backup.id])
        if restore_drill is not None:
            fields.extend(["last_restore_drill_at=?", "last_restore_drill_ok=?"])
            values.extend([now, int(bool(restore_drill))])
        values.append(1)
        self.store.conn.execute(f"UPDATE runtime_state SET {', '.join(fields)} WHERE singleton=?", tuple(values))

    def boot(self, *, now: float | None = None) -> dict[str, int]:
        when = time.time() if now is None else float(now)
        self.store.conn.execute(
            "UPDATE runtime_state SET state='STARTING',boot_count=boot_count+1,started_at=?,heartbeat_at=?,last_error=NULL WHERE singleton=1",
            (when, when),
        )
        summary = self.engine.resume(now=when)
        self._update_state("RUNNING", now=when)
        self.audit.append(
            actor="continuous-supervisor",
            action="continuous_runtime_booted",
            payload={"recovered_leases": summary.get("recovered_leases", 0)},
            now=when,
        )
        return summary

    @staticmethod
    def _sqlite_integrity(path: str | Path) -> bool:
        try:
            conn = sqlite3.connect(f"file:{Path(path).resolve().as_posix()}?mode=ro", uri=True, timeout=10)
            try:
                row = conn.execute("PRAGMA integrity_check").fetchone()
                return bool(row and str(row[0]).lower() == "ok")
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    def _restore_drill(self, ref: BackupRef, *, now: float) -> bool:
        with tempfile.TemporaryDirectory(prefix="immune-restore-drill-") as td:
            target = Path(td) / "state.sqlite3"
            try:
                restored = self.backups.restore_to(ref, target, now=now)
                return self._sqlite_integrity(restored)
            except Exception as exc:
                self.audit.append(
                    actor="continuous-supervisor",
                    action="restore_drill_failed",
                    payload={"backup_id": ref.id, "error": type(exc).__name__},
                    now=now,
                )
                return False

    def _prune_backups(self) -> int:
        manifests: list[tuple[float, str]] = []
        for path in self.backups.root.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                manifests.append((float(data["created_at"]), str(data["id"])))
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue
        manifests.sort(reverse=True)
        removed = 0
        for _, backup_id in manifests[self.backup_retention:]:
            for suffix in (".json", ".sqlite3"):
                target = self.backups.root / f"{backup_id}{suffix}"
                if target.exists():
                    target.unlink()
                    removed += 1
        return removed

    def tick(self, *, now: float | None = None) -> RuntimeCycle:
        started = time.time() if now is None else float(now)
        recovered = self.store.recover_expired_leases(now=started)
        probes_ok = 0
        probes_failed = 0
        probe_results: dict[str, dict[str, object]] = {}

        for name, probe in sorted(self.probes.items()):
            try:
                ok = bool(probe())
                error = None if ok else "probe returned false"
            except Exception as exc:
                ok = False
                error = f"{type(exc).__name__}: {exc}"
            self.observability.update_sensor_health(f"self:{name}", ok=ok, error=error, ts=started)
            probe_results[name] = {"ok": ok, "error": error}
            probes_ok += int(ok)
            probes_failed += int(not ok)

        state_row = self.status()
        backup: BackupRef | None = None
        last_backup_at = state_row.get("last_backup_at")
        if last_backup_at is None or started - float(last_backup_at) >= self.backup_interval_seconds:
            try:
                backup = self.backups.create(now=started)
                if not self.backups.verify(backup):
                    raise ContinuousOperationError("periodic backup verification failed")
                self._prune_backups()
            except Exception as exc:
                probes_failed += 1
                probe_results["periodic_backup"] = {"ok": False, "error": type(exc).__name__}

        effective_backup = backup
        if effective_backup is None and state_row.get("last_backup_id"):
            try:
                effective_backup = self.backups.get(str(state_row["last_backup_id"]))
            except Exception:
                effective_backup = None

        restore_ok: bool | None = None
        last_drill_at = state_row.get("last_restore_drill_at")
        due_drill = last_drill_at is None or started - float(last_drill_at) >= self.restore_drill_interval_seconds
        if due_drill and effective_backup is not None:
            restore_ok = self._restore_drill(effective_backup, now=started)
            if not restore_ok:
                probes_failed += 1
                probe_results["restore_drill"] = {"ok": False, "error": "restore drill failed"}

        state = "DEGRADED" if probes_failed else "RUNNING"
        completed = time.time() if now is None else float(now)
        evidence = self.observability.evidence(
            kind="continuous_runtime_cycle",
            payload={
                "state": state,
                "recovered_leases": recovered,
                "probes": probe_results,
                "backup_id": backup.id if backup else None,
                "restore_drill_ok": restore_ok,
            },
            ts=completed,
        )
        cycle_id = str(uuid.uuid4())
        self.store.conn.execute(
            "INSERT INTO runtime_cycles(id,started_at,completed_at,state,recovered_leases,probes_ok,probes_failed,backup_id,restore_drill_ok,evidence_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (cycle_id, started, completed, state, recovered, probes_ok, probes_failed, backup.id if backup else None, None if restore_ok is None else int(restore_ok), evidence.id),
        )
        self._update_state(
            state,
            now=completed,
            error="one or more runtime checks failed" if probes_failed else None,
            backup=backup,
            restore_drill=restore_ok,
        )
        self.audit.append(
            actor="continuous-supervisor",
            action="continuous_runtime_cycle",
            payload={"cycle_id": cycle_id, "state": state, "recovered_leases": recovered, "probes_failed": probes_failed, "backup_id": backup.id if backup else None, "evidence_id": evidence.id},
            now=completed,
        )
        return RuntimeCycle(cycle_id, started, completed, state, recovered, probes_ok, probes_failed, backup.id if backup else None, restore_ok, evidence.id)

    def run_for(self, duration_seconds: float, *, interval_seconds: float = 0.05, max_cycles: int = 10000) -> dict[str, object]:
        if duration_seconds <= 0 or interval_seconds < 0 or max_cycles < 1:
            raise ValueError("invalid continuous runtime bounds")
        started = time.monotonic()
        cycles = 0
        degraded = 0
        while time.monotonic() - started < duration_seconds and cycles < max_cycles:
            cycle_started = time.monotonic()
            result = self.tick()
            cycles += 1
            degraded += int(result.state != "RUNNING")
            if interval_seconds:
                # interval_seconds is a target start-to-start cadence, not extra delay.
                # Never sleep again for work time already consumed by the cycle itself.
                remaining = interval_seconds - (time.monotonic() - cycle_started)
                if remaining > 0:
                    time.sleep(remaining)
        return {"duration_seconds": time.monotonic() - started, "cycles": cycles, "degraded_cycles": degraded, "state": self.status()["state"]}

    def stop(self, *, now: float | None = None) -> None:
        when = time.time() if now is None else float(now)
        self._update_state("STOPPED", now=when)
        self.audit.append(actor="continuous-supervisor", action="continuous_runtime_stopped", payload={}, now=when)
