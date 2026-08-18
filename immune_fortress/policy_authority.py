from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from immune_core.identity import IdentityAuthority
from immune_core.models import PolicyDecision
from immune_core.policy import PolicyGuard
from immune_core.storage import SQLiteStateStore

from .capability import ActionCapability, ActionCapabilityAuthority


class SovereignAuthorizationError(RuntimeError):
    pass


ACTIVE_STATES = {"AUTHORIZED", "DISCOVERING", "RUNNING", "DEGRADED", "VALIDATING"}


@dataclass(frozen=True)
class ActionRule:
    required_scope: str
    material_change: bool
    irreversible: bool = False
    checkpoint_required: bool = True


@dataclass(frozen=True)
class ActionIntent:
    mission_id: str
    system_id: str
    action: str
    parameters: dict[str, Any]
    checkpoint_id: str | None = None


@dataclass(frozen=True)
class AuthorizedAction:
    decision: PolicyDecision
    capability: ActionCapability


class SovereignPolicyAuthority:
    """Ring 3 authority. Authorization facts are derived, never accepted as caller booleans."""

    def __init__(
        self,
        store: SQLiteStateStore,
        identities: IdentityAuthority,
        policy: PolicyGuard,
        capabilities: ActionCapabilityAuthority,
        action_catalog: Mapping[str, Mapping[str, ActionRule]],
        *,
        checkpoint_verifier: Callable[[str, ActionIntent], bool],
        recovery_verifier: Callable[[str | None, ActionIntent], bool],
    ) -> None:
        self.store = store
        self.identities = identities
        self.policy = policy
        self.capabilities = capabilities
        self.action_catalog = {sid: dict(actions) for sid, actions in action_catalog.items()}
        self.checkpoint_verifier = checkpoint_verifier
        self.recovery_verifier = recovery_verifier

    def _rule(self, intent: ActionIntent) -> ActionRule:
        try:
            return self.action_catalog[intent.system_id][intent.action]
        except KeyError as exc:
            raise SovereignAuthorizationError("action is not present in sovereign action catalog") from exc

    def authorize(self, requester_token: str, intent: ActionIntent, *, now: int | None = None) -> AuthorizedAction:
        mission = self.store.get_mission(intent.mission_id)
        rule = self._rule(intent)
        mission_authorized = mission is not None and str(mission["state"]) in ACTIVE_STATES
        system_authorized = mission is not None and str(mission["system_id"]) == intent.system_id
        scope_ok = bool(rule.required_scope)
        checkpoint_valid = True
        if rule.checkpoint_required or rule.material_change:
            checkpoint_valid = bool(intent.checkpoint_id and self.checkpoint_verifier(intent.checkpoint_id, intent))
        recovery_verified = bool(self.recovery_verifier(intent.checkpoint_id, intent)) if rule.irreversible else True
        decision = self.policy.evaluate_token(
            requester_token,
            {
                "mission_id": intent.mission_id,
                "action": intent.action,
                "required_scope": rule.required_scope,
                "mission_authorized": mission_authorized,
                "system_authorized": system_authorized,
                "scope_ok": scope_ok,
                "material_change": rule.material_change,
                "checkpoint_valid": checkpoint_valid,
                "irreversible": rule.irreversible,
                "recovery_verified": recovery_verified,
            },
            now=now,
        )
        if not decision.permitted:
            raise SovereignAuthorizationError(f"{decision.decision}: {decision.reason}")
        capability_issuer = self.identities.issue(
            "sovereign-policy-authority", "policy", ("capability:issue",), ttl_seconds=60, now=now
        )
        capability = self.capabilities.issue(
            capability_issuer,
            mission_id=intent.mission_id,
            system_id=intent.system_id,
            action=intent.action,
            parameters=intent.parameters,
            checkpoint_id=intent.checkpoint_id,
            now=now,
        )
        return AuthorizedAction(decision, capability)
