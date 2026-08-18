from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .execution import WorkerManifest


@dataclass(frozen=True)
class WorkerOutcome:
    task_id: str | None
    state: str
    returncode: int | None = None
    rolled_back: bool = False
    detail: str = ""


class WorkerRunner(Protocol):
    """Core-side contract only. Concrete execution lives in immune_execution_broker."""

    def run_once(self, manifest: WorkerManifest, worker_token: str, *, privilege_authorizer_token: str | None = None, now: int | None = None, mission_id: str | None = None) -> WorkerOutcome:
        ...
