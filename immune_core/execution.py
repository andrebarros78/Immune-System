from __future__ import annotations

from dataclasses import dataclass


class ExecutionError(RuntimeError):
    pass


class AuthorizationError(ExecutionError):
    pass


ACTIVE_EXECUTION_STATES = {"AUTHORIZED", "DISCOVERING", "RUNNING", "DEGRADED", "VALIDATING"}


@dataclass(frozen=True)
class WorkerManifest:
    id: str
    kinds: tuple[str, ...]
    capabilities: tuple[str, ...]
    authority: str
    allowed_executables: tuple[str, ...]
    max_runtime_seconds: float = 60.0
    max_output_bytes: int = 1_000_000
    env_allowlist: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.kinds or not self.capabilities or not self.allowed_executables:
            raise ValueError("worker manifest requires identity, kinds, capabilities and executable allowlist")
        if self.authority not in {"task-scoped", "privileged-ephemeral"}:
            raise ValueError("invalid worker authority")
        if self.max_runtime_seconds <= 0 or self.max_output_bytes < 1024:
            raise ValueError("invalid worker limits")


@dataclass(frozen=True)
class ExecutionResult:
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    checkpoint_id: str | None
    rolled_back: bool
    policy_decision: str
