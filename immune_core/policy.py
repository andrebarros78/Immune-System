from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .audit import AuditLedger
from .identity import IdentityAuthority, IdentityError
from .models import PolicyDecision, Principal


class PolicyGuard:
    """Governador executável, fail-closed, subordinado ao IMUNE-DNA."""

    POLICY_VERSION = "IMUNE-DNA-001/1.0.0"

    def __init__(
        self,
        identity: IdentityAuthority,
        audit: AuditLedger,
        *,
        constitution_path: str | Path,
        expected_constitution_sha256: str,
    ):
        self.identity = identity
        self.audit = audit
        self.constitution_path = Path(constitution_path)
        self.expected_constitution_sha256 = expected_constitution_sha256

    @classmethod
    def from_repository(cls, root: str | Path, identity: IdentityAuthority, audit: AuditLedger) -> "PolicyGuard":
        root = Path(root)
        evidence = json.loads((root / "evidence/phase1-validation.json").read_text(encoding="utf-8"))
        expected = evidence["controlled_file_sha256"]["constitution/IMUNE-DNA-001.md"]
        return cls(
            identity,
            audit,
            constitution_path=root / "constitution/IMUNE-DNA-001.md",
            expected_constitution_sha256=expected,
        )

    def _constitution_ok(self) -> bool:
        try:
            actual = hashlib.sha256(self.constitution_path.read_bytes()).hexdigest()
        except OSError:
            return False
        return actual == self.expected_constitution_sha256

    def _record(self, principal: Principal | None, request: dict[str, Any], decision: PolicyDecision) -> PolicyDecision:
        self.audit.append(
            actor=principal.subject if principal else "unverified",
            action="policy_decision",
            mission_id=request.get("mission_id"),
            payload={
                "request_action": request.get("action"),
                "decision": decision.decision,
                "reason": decision.reason,
                "restrictions": list(decision.restrictions),
                "policy_version": decision.policy_version,
            },
        )
        return decision

    def evaluate_token(self, token: str, request: dict[str, Any], *, now: int | None = None) -> PolicyDecision:
        required_scope = str(request.get("required_scope", "")).strip() or None
        try:
            principal = self.identity.verify(token, required_scope=required_scope, now=now)
        except IdentityError as exc:
            return self._record(
                None,
                request,
                PolicyDecision("BLOQUEAR", f"identidade inválida: {exc}", policy_version=self.POLICY_VERSION),
            )
        return self._evaluate_verified(principal, request)

    def _evaluate_verified(self, principal: Principal, request: dict[str, Any]) -> PolicyDecision:
        if not self._constitution_ok():
            return self._record(
                principal,
                request,
                PolicyDecision("BLOQUEAR", "constituição ausente ou hash divergente", policy_version=self.POLICY_VERSION),
            )

        required = ("mission_authorized", "system_authorized", "scope_ok")
        if not all(request.get(name) is True for name in required):
            return self._record(
                principal,
                request,
                PolicyDecision("BLOQUEAR", "missão, sistema ou escopo não autorizado", policy_version=self.POLICY_VERSION),
            )

        required_scope = str(request.get("required_scope", "")).strip()
        if required_scope and not principal.has_scope(required_scope):
            return self._record(
                principal,
                request,
                PolicyDecision("BLOQUEAR", "identidade sem escopo exigido", policy_version=self.POLICY_VERSION),
            )

        if any(
            request.get(name) is True
            for name in ("new_cost", "purchase", "subscription", "trial_with_billing_risk", "commercial_license")
        ):
            return self._record(
                principal,
                request,
                PolicyDecision(
                    "EXIGIR_APROVAÇÃO_HUMANA",
                    "ação financeira exige autorização humana explícita",
                    policy_version=self.POLICY_VERSION,
                ),
            )

        if request.get("disables_security_control") is True:
            return self._record(
                principal,
                request,
                PolicyDecision("BLOQUEAR", "controle de segurança não pode ser desativado", policy_version=self.POLICY_VERSION),
            )

        if request.get("logs_plaintext_secret") is True or request.get("prompt_contains_unredacted_secret") is True:
            return self._record(
                principal,
                request,
                PolicyDecision("BLOQUEAR", "segredo em texto aberto é proibido", policy_version=self.POLICY_VERSION),
            )

        if request.get("irreversible") is True and request.get("recovery_verified") is not True:
            return self._record(
                principal,
                request,
                PolicyDecision(
                    "EXIGIR_APROVAÇÃO_HUMANA",
                    "ação irreversível sem recuperação comprovada",
                    policy_version=self.POLICY_VERSION,
                ),
            )

        if request.get("material_change") is True and request.get("checkpoint_valid") is not True:
            return self._record(
                principal,
                request,
                PolicyDecision("EXIGIR_CHECKPOINT", "mudança material exige checkpoint válido", policy_version=self.POLICY_VERSION),
            )

        if request.get("donor_component") is True:
            gates = (
                "open_source",
                "license_verified",
                "origin_pinned",
                "artifact_hash_verified",
                "security_scanned",
                "laboratory_approved",
            )
            if not all(request.get(name) is True for name in gates) or request.get("authority") != "adapter-only":
                return self._record(
                    principal,
                    request,
                    PolicyDecision("BLOQUEAR", "doador não passou por todos os gates OSS", policy_version=self.POLICY_VERSION),
                )
            return self._record(
                principal,
                request,
                PolicyDecision(
                    "PERMITIR_COM_RESTRIÇÕES",
                    "doador aprovado somente por adapter",
                    ("no_direct_execution", "policy_guard_required"),
                    self.POLICY_VERSION,
                ),
            )

        return self._record(
            principal,
            request,
            PolicyDecision("PERMITIR", "ação autorizada dentro da missão", policy_version=self.POLICY_VERSION),
        )
