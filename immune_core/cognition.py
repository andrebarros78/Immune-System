from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from .audit import AuditLedger
from .engine import DurableLoopEngine
from .memory import CognitiveMemory
from .models import PolicyDecision
from .policy import PolicyGuard
from .providers import ProviderManager, ProviderProposal, ProviderRequest
from .skills import SkillError, SkillRegistry
from .storage import SQLiteStateStore


class CognitionError(RuntimeError):
    pass


COGNITIVE_MISSION_STATES = {"AUTHORIZED", "DISCOVERING", "RUNNING", "DEGRADED", "VALIDATING"}


@dataclass(frozen=True)
class QueueResult:
    queued_task_ids: tuple[str, ...]
    rejected: tuple[dict[str, str], ...]


class CognitiveCore:
    """Builds diagnostic proposals. It has no executor, shell, tool or privilege interface."""

    def __init__(
        self,
        providers: ProviderManager,
        memory: CognitiveMemory,
        skills: SkillRegistry,
        audit: AuditLedger,
    ):
        self.providers = providers
        self.memory = memory
        self.skills = skills
        self.audit = audit

    def propose(
        self,
        *,
        mission_id: str,
        objective: str,
        observations: Iterable[dict[str, Any]] = (),
        requested_skills: Iterable[tuple[str, str | None]] = (),
        memory_kind: str | None = None,
        paid_authorizer_token: str | None = None,
        max_cost: float = 0.0,
        timeout_seconds: float = 15.0,
        now: int | None = None,
    ) -> ProviderProposal:
        promoted = self.memory.recall_promoted(kind=memory_kind, mission_id=mission_id, limit=20)
        memory_context = tuple(
            {
                "memory_id": item.id,
                "kind": item.kind,
                "content": item.content,
                "evidence_ids": list(item.evidence_ids),
                "confidence": item.confidence,
                "state": item.state,
            }
            for item in promoted
        )
        skill_context: list[dict[str, Any]] = []
        for skill_id, version in requested_skills:
            skill = self.skills.resolve_approved(skill_id, version)
            skill_context.append(
                {
                    "skill_id": skill.skill_id,
                    "version": skill.version,
                    "capability": skill.capability,
                    "donor_id": skill.donor_id,
                    "authority": skill.authority,
                    "executable": False,
                }
            )
        request = ProviderRequest(
            mission_id=mission_id,
            objective=objective,
            untrusted_observations=tuple(dict(x) for x in observations),
            validated_memory=memory_context,
            skill_context=tuple(skill_context),
        )
        proposal = self.providers.propose(
            request,
            timeout_seconds=timeout_seconds,
            paid_authorizer_token=paid_authorizer_token,
            max_cost=max_cost,
            now=now,
        )
        self.audit.append(
            actor="cognitive-core",
            action="cognitive_proposal_created",
            mission_id=mission_id,
            payload={
                "provider_id": proposal.provider_id,
                "task_count": len(proposal.recommended_tasks),
                "memory_count": len(memory_context),
                "skill_count": len(skill_context),
                "degraded": proposal.degraded,
            },
        )
        return proposal

    def quarantine_learning(
        self,
        *,
        mission_id: str,
        proposal: ProviderProposal,
        outcome: dict[str, Any],
        evidence_ids: Iterable[str],
    ) -> str:
        return self.memory.record(
            kind="cognitive-outcome",
            source=f"provider:{proposal.provider_id}",
            mission_id=mission_id,
            evidence_ids=tuple(evidence_ids),
            confidence=proposal.confidence,
            content={
                "proposal_summary": proposal.summary,
                "hypotheses": list(proposal.hypotheses),
                "outcome": dict(outcome),
            },
        )


class CognitiveCoordinator:
    """The only cognition-to-action bridge. It can queue, never execute, and every task is PolicyGuard-gated."""

    def __init__(
        self,
        store: SQLiteStateStore,
        engine: DurableLoopEngine,
        policy: PolicyGuard,
        skills: SkillRegistry,
        audit: AuditLedger,
    ):
        self.store = store
        self.engine = engine
        self.policy = policy
        self.skills = skills
        self.audit = audit

    @staticmethod
    def _policy_request(mission_id: str, task: dict[str, Any], mission_state: str) -> dict[str, Any]:
        risk = dict(task.get("risk", {})) if isinstance(task.get("risk", {}), dict) else {}
        allowed_risk = {
            "new_cost",
            "purchase",
            "subscription",
            "trial_with_billing_risk",
            "commercial_license",
            "disables_security_control",
            "logs_plaintext_secret",
            "prompt_contains_unredacted_secret",
            "irreversible",
            "recovery_verified",
        }
        request: dict[str, Any] = {
            "mission_id": mission_id,
            "action": "enqueue_cognitive_proposal",
            "required_scope": "cognition:authorize",
            "mission_authorized": mission_state in COGNITIVE_MISSION_STATES,
            "system_authorized": True,
            "scope_ok": True,
            "material_change": False,
        }
        for key in allowed_risk:
            if key in risk:
                request[key] = risk[key]
        return request

    @staticmethod
    def _idempotency_key(mission_id: str, provider_id: str, index: int, task: dict[str, Any]) -> str:
        canonical = json.dumps(task, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(f"{mission_id}|{provider_id}|{index}|{canonical}".encode("utf-8")).hexdigest()
        return f"cognition:{digest}"

    def queue_proposal(
        self,
        *,
        mission_id: str,
        proposal: ProviderProposal,
        controller_token: str,
        priority: int = 0,
        max_attempts: int = 3,
        now: int | None = None,
    ) -> QueueResult:
        mission = self.store.get_mission(mission_id)
        if not mission:
            raise CognitionError("mission not found")
        mission_state = str(mission["state"])
        queued: list[str] = []
        rejected: list[dict[str, str]] = []
        for index, task in enumerate(proposal.recommended_tasks):
            skill_id = task.get("skill_id")
            if skill_id:
                try:
                    self.skills.resolve_approved(str(skill_id))
                except SkillError as exc:
                    rejected.append({"index": str(index), "reason": f"skill gate: {exc}"})
                    continue
            decision: PolicyDecision = self.policy.evaluate_token(
                controller_token,
                self._policy_request(mission_id, task, mission_state),
                now=now,
            )
            if not decision.permitted:
                rejected.append({"index": str(index), "reason": f"{decision.decision}: {decision.reason}"})
                self.audit.append(
                    actor="cognitive-coordinator",
                    action="cognitive_task_rejected",
                    mission_id=mission_id,
                    payload={"index": index, "provider_id": proposal.provider_id, "decision": decision.decision, "reason": decision.reason},
                )
                continue
            payload = dict(task.get("payload", {}))
            payload["cognitive_provenance"] = {
                "provider_id": proposal.provider_id,
                "proposal_confidence": proposal.confidence,
                "skill_id": skill_id,
            }
            task_id = self.engine.submit_task(
                mission_id,
                str(task["kind"]),
                payload,
                idempotency_key=self._idempotency_key(mission_id, proposal.provider_id, index, task),
                priority=priority,
                max_attempts=max_attempts,
                now=float(now) if now is not None else None,
            )
            queued.append(task_id)
            self.audit.append(
                actor="cognitive-coordinator",
                action="cognitive_task_queued",
                mission_id=mission_id,
                payload={"task_id": task_id, "provider_id": proposal.provider_id, "index": index, "skill_id": skill_id},
            )
        return QueueResult(tuple(queued), tuple(rejected))
