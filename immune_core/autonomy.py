from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from .audit import AuditLedger
from .cognition import CognitiveCoordinator, CognitiveCore, QueueResult
from .execution import WorkerManifest
from .memory import MemoryRecord
from .models import PolicyDecision
from .storage import SQLiteStateStore
from .update_manager import ActivationResult, ReleaseManager, StagedRelease
from .workers import WorkerOutcome, WorkerRunner


class AutonomyError(RuntimeError):
    pass


ACTIVE_MISSION_STATES = {"AUTHORIZED", "DISCOVERING", "RUNNING", "DEGRADED", "VALIDATING"}


@dataclass(frozen=True)
class InternalAgentSpec:
    id: str
    purpose: str
    uses_cognitive_provider: bool
    can_authorize: bool = False
    can_execute: bool = False
    provider_scope: str | None = None


class InternalAgentRegistry:
    """Fixed internal roles. External systems never inherit these agents or their provider access."""

    DEFAULTS = (
        InternalAgentSpec("observer", "collect and normalize health evidence", False),
        InternalAgentSpec("diagnostician", "form and discriminate causal hypotheses", True, provider_scope="immune-core"),
        InternalAgentSpec("researcher", "research unknown technology and candidate repairs", True, provider_scope="immune-core"),
        InternalAgentSpec("repair-planner", "propose bounded reversible repair tasks", True, provider_scope="immune-core"),
        InternalAgentSpec("policy-guardian", "evaluate authority, cost, reversibility and safety", False, can_authorize=True),
        InternalAgentSpec("executor", "execute only policy-approved task leases", False, can_execute=True),
        InternalAgentSpec("validator", "verify recovery, regression and acceptance evidence", False),
        InternalAgentSpec("recovery", "restore checkpoints and contain failed changes", False, can_execute=True),
        InternalAgentSpec("learner", "promote only independently validated reusable knowledge", False),
        InternalAgentSpec("updater", "activate verified releases and roll back failed health checks", False, can_execute=True),
    )

    def __init__(self, agents: Iterable[InternalAgentSpec] | None = None):
        values = tuple(agents or self.DEFAULTS)
        ids = [agent.id for agent in values]
        if len(ids) != len(set(ids)):
            raise ValueError("internal agent ids must be unique")
        for agent in values:
            if agent.uses_cognitive_provider and agent.provider_scope != "immune-core":
                raise ValueError("cognitive agents must use immune-core-exclusive provider scope")
        self._agents = {agent.id: agent for agent in values}

    def get(self, agent_id: str) -> InternalAgentSpec:
        try:
            return self._agents[agent_id]
        except KeyError as exc:
            raise AutonomyError(f"internal agent not registered: {agent_id}") from exc

    def public_view(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            {
                "id": agent.id,
                "purpose": agent.purpose,
                "uses_cognitive_provider": agent.uses_cognitive_provider,
                "can_authorize": agent.can_authorize,
                "can_execute": agent.can_execute,
                "provider_scope": agent.provider_scope,
            }
            for agent in self._agents.values()
        )


@dataclass(frozen=True)
class WorkerBinding:
    manifest: WorkerManifest
    worker_token: str
    privilege_authorizer_token: str | None = None


@dataclass(frozen=True)
class AutonomyCycleResult:
    mission_id: str
    state: str
    provider_id: str
    proposal_degraded: bool
    queued_task_ids: tuple[str, ...]
    rejected: tuple[dict[str, str], ...]
    worker_outcomes: tuple[WorkerOutcome, ...]
    learning_memory_id: str | None
    learning_promoted: bool
    evidence_id: str
    started_at: float
    completed_at: float


class AutonomousMaintenanceController:
    """Closed loop: provider proposes, PolicyGuard authorizes, Workers execute, validator proves."""

    def __init__(self, store: SQLiteStateStore, core: CognitiveCore, coordinator: CognitiveCoordinator, runner: WorkerRunner, audit: AuditLedger, *, agents: InternalAgentRegistry | None = None):
        self.store = store
        self.core = core
        self.coordinator = coordinator
        self.runner = runner
        self.audit = audit
        self.agents = agents or InternalAgentRegistry()

    def _mission_state(self, mission_id: str) -> str:
        mission = self.store.get_mission(mission_id)
        if mission is None:
            raise AutonomyError("mission not found")
        state = str(mission["state"])
        if state not in ACTIVE_MISSION_STATES:
            raise AutonomyError(f"mission is not autonomous-active: {state}")
        return state

    @staticmethod
    def _next_queued_task(tasks: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
        queued = [task for task in tasks if str(task.get("state")) == "QUEUED"]
        if not queued:
            return None
        queued.sort(key=lambda task: (-int(task.get("priority", 0)), float(task.get("created_at", 0.0)), str(task.get("id", ""))))
        return queued[0]

    @staticmethod
    def _binding_for_task(task: dict[str, Any], bindings: Sequence[WorkerBinding]) -> WorkerBinding | None:
        kind = str(task.get("kind", ""))
        return next((binding for binding in bindings if kind in binding.manifest.kinds), None)

    def run_cycle(
        self,
        *,
        mission_id: str,
        objective: str,
        controller_token: str,
        workers: Sequence[WorkerBinding],
        observations: Iterable[dict[str, Any]] = (),
        requested_skills: Iterable[tuple[str, str | None]] = (),
        memory_kind: str | None = None,
        max_worker_steps: int = 16,
        timeout_seconds: float = 15.0,
        paid_authorizer_token: str | None = None,
        max_cost: float = 0.0,
        memory_validator_token: str | None = None,
        independent_validation: Callable[[AutonomyCycleResult], bool] | None = None,
        min_learning_confidence: float = 0.70,
        now: int | None = None,
    ) -> AutonomyCycleResult:
        if not objective.strip():
            raise ValueError("objective is required")
        if max_worker_steps < 0 or max_worker_steps > 256:
            raise ValueError("max_worker_steps outside 0..256")
        if not 0.0 <= min_learning_confidence <= 1.0:
            raise ValueError("min_learning_confidence outside 0..1")
        self._mission_state(mission_id)
        started = time.time() if now is None else float(now)
        observation_items = tuple(dict(item) for item in observations)
        self.audit.append(
            actor="agent:observer",
            action="autonomy_observation_cycle",
            mission_id=mission_id,
            payload={"objective": objective, "observation_count": len(observation_items)},
            now=started,
        )

        proposal = self.core.propose(
            mission_id=mission_id,
            objective=objective,
            observations=observation_items,
            requested_skills=requested_skills,
            memory_kind=memory_kind,
            paid_authorizer_token=paid_authorizer_token,
            max_cost=max_cost,
            timeout_seconds=timeout_seconds,
            now=now,
        )
        queue: QueueResult = self.coordinator.queue_proposal(
            mission_id=mission_id,
            proposal=proposal,
            controller_token=controller_token,
            now=now,
        )

        outcomes: list[WorkerOutcome] = []
        for _ in range(max_worker_steps):
            task = self._next_queued_task(self.store.list_tasks(mission_id))
            if task is None:
                break
            binding = self._binding_for_task(task, workers)
            if binding is None:
                self.audit.append(
                    actor="agent:executor",
                    action="autonomy_worker_unavailable",
                    mission_id=mission_id,
                    payload={"task_id": task.get("id"), "kind": task.get("kind")},
                )
                break
            outcome = self.runner.run_once(
                binding.manifest,
                binding.worker_token,
                privilege_authorizer_token=binding.privilege_authorizer_token,
                now=now,
                mission_id=mission_id,
            )
            outcomes.append(outcome)
            if outcome.state == "IDLE":
                break

        task_states = [str(task["state"]) for task in self.store.list_tasks(mission_id)]
        if proposal.degraded:
            cycle_state = "DEGRADED_NO_AI"
        elif any(state in {"FAILED", "BLOCKED"} for state in task_states):
            cycle_state = "FAILED_SAFE"
        elif any(state in {"QUEUED", "RUNNING"} for state in task_states):
            cycle_state = "PARTIAL"
        elif queue.queued_task_ids and all(
            self.store.get_task(task_id) and self.store.get_task(task_id)["state"] == "COMPLETED"
            for task_id in queue.queued_task_ids
        ):
            cycle_state = "COMPLETED"
        else:
            cycle_state = "IDLE"

        completed = time.time() if now is None else float(now)
        evidence_id = self.audit.append(
            actor="agent:validator",
            action="autonomy_cycle_validated",
            mission_id=mission_id,
            payload={
                "state": cycle_state,
                "provider_id": proposal.provider_id,
                "queued": len(queue.queued_task_ids),
                "rejected": len(queue.rejected),
                "worker_outcomes": [
                    {
                        "task_id": outcome.task_id,
                        "state": outcome.state,
                        "returncode": outcome.returncode,
                        "rolled_back": outcome.rolled_back,
                    }
                    for outcome in outcomes
                ],
            },
            now=completed,
        )

        learning_memory_id: str | None = None
        learning_promoted = False
        if not proposal.degraded and (queue.queued_task_ids or proposal.hypotheses):
            learning_memory_id = self.core.quarantine_learning(
                mission_id=mission_id,
                proposal=proposal,
                outcome={
                    "cycle_state": cycle_state,
                    "task_states": task_states,
                    "rejected": list(queue.rejected),
                },
                evidence_ids=(evidence_id,),
            )

        provisional = AutonomyCycleResult(
            mission_id=mission_id,
            state=cycle_state,
            provider_id=proposal.provider_id,
            proposal_degraded=proposal.degraded,
            queued_task_ids=queue.queued_task_ids,
            rejected=queue.rejected,
            worker_outcomes=tuple(outcomes),
            learning_memory_id=learning_memory_id,
            learning_promoted=False,
            evidence_id=evidence_id,
            started_at=started,
            completed_at=completed,
        )

        if (
            learning_memory_id
            and memory_validator_token
            and independent_validation
            and cycle_state == "COMPLETED"
            and not queue.rejected
            and proposal.confidence >= min_learning_confidence
            and bool(independent_validation(provisional))
        ):
            promoted: MemoryRecord = self.core.memory.promote(
                learning_memory_id,
                memory_validator_token,
                validated_evidence_ids=(evidence_id,),
                independent_validation=True,
                reproducible=True,
                now=now,
            )
            learning_promoted = promoted.state == "PROMOTED"
            self.audit.append(
                actor="agent:learner",
                action="autonomy_learning_promoted",
                mission_id=mission_id,
                payload={"memory_id": learning_memory_id, "evidence_id": evidence_id},
                now=completed,
            )

        return AutonomyCycleResult(
            mission_id=provisional.mission_id,
            state=provisional.state,
            provider_id=provisional.provider_id,
            proposal_degraded=provisional.proposal_degraded,
            queued_task_ids=provisional.queued_task_ids,
            rejected=provisional.rejected,
            worker_outcomes=provisional.worker_outcomes,
            learning_memory_id=provisional.learning_memory_id,
            learning_promoted=learning_promoted,
            evidence_id=provisional.evidence_id,
            started_at=provisional.started_at,
            completed_at=provisional.completed_at,
        )


class AutonomousUpdateAgent:
    """Activates only a pre-verified staged release after PolicyGuard authorization."""

    def __init__(self, releases: ReleaseManager, audit: AuditLedger):
        self.releases = releases
        self.audit = audit

    def activate(
        self,
        *,
        mission_id: str,
        staged: StagedRelease,
        policy_decision: PolicyDecision,
        health_check: Callable[[Any], bool],
        now: float | None = None,
    ) -> ActivationResult:
        if not policy_decision.permitted:
            raise AutonomyError(f"update blocked by policy: {policy_decision.decision}")
        result = self.releases.activate(staged, health_check, now=now)
        self.audit.append(
            actor="agent:updater",
            action="autonomous_update_result",
            mission_id=mission_id,
            payload={
                "version": result.version,
                "active": result.active,
                "rolled_back": result.rolled_back,
                "backup_id": result.backup_id,
            },
            now=now,
        )
        return result
