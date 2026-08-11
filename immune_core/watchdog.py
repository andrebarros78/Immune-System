from __future__ import annotations

import time
from dataclasses import dataclass

from .storage import SQLiteStateStore


@dataclass(frozen=True)
class WatchdogStatus:
    state: str
    runtime_state: str | None
    heartbeat_age_seconds: float | None
    reason: str


class HeartbeatWatchdog:
    """Read-only watchdog for the supervisor heartbeat.

    It has no execution authority. An OS service manager may use STALE as a
    restart signal, while Core remains the only sovereign state owner.
    """

    def __init__(self, store: SQLiteStateStore, *, stale_after_seconds: float = 30.0):
        self.store = store
        self.stale_after_seconds = float(stale_after_seconds)
        if self.stale_after_seconds <= 0:
            raise ValueError("stale_after_seconds must be positive")

    def check(self, *, now: float | None = None) -> WatchdogStatus:
        when = time.time() if now is None else float(now)
        exists = self.store.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_state'"
        ).fetchone()
        if not exists:
            return WatchdogStatus("UNKNOWN", None, None, "runtime state not initialized")
        row = self.store.conn.execute(
            "SELECT state,heartbeat_at FROM runtime_state WHERE singleton=1"
        ).fetchone()
        if row is None or row["heartbeat_at"] is None:
            return WatchdogStatus("STALE", str(row["state"]) if row else None, None, "heartbeat missing")
        age = max(0.0, when - float(row["heartbeat_at"]))
        runtime_state = str(row["state"])
        if runtime_state == "STOPPED":
            return WatchdogStatus("STOPPED", runtime_state, age, "runtime stopped intentionally")
        if age > self.stale_after_seconds:
            return WatchdogStatus("STALE", runtime_state, age, "supervisor heartbeat expired")
        if runtime_state in {"DEGRADED", "FAILED_SAFE"}:
            return WatchdogStatus("DEGRADED", runtime_state, age, "supervisor reports degraded state")
        return WatchdogStatus("HEALTHY", runtime_state, age, "heartbeat fresh")
