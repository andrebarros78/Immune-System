from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from immune_lab.admission import Decision, REQUIRED_EVIDENCE, evaluate_donor

from .audit import AuditLedger
from .identity import IdentityAuthority
from .storage import SQLiteStateStore


class SkillError(RuntimeError):
    pass


@dataclass(frozen=True)
class SkillRecord:
    skill_id: str
    version: str
    capability: str
    donor_id: str
    state: str
    authority: str
    executable: bool
    evidence: dict[str, bool]
    donor: dict[str, Any]
    created_at: float
    updated_at: float


class SkillRegistry:
    """Versioned skill lifecycle. Skills never receive execution authority."""

    def __init__(self, store: SQLiteStateStore, identity: IdentityAuthority, audit: AuditLedger):
        self.store = store
        self.identity = identity
        self.audit = audit
        self.store.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cognitive_skills (
                skill_id TEXT NOT NULL,
                version TEXT NOT NULL,
                capability TEXT NOT NULL,
                donor_id TEXT NOT NULL,
                donor_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                state TEXT NOT NULL,
                authority TEXT NOT NULL,
                executable INTEGER NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY(skill_id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_cognitive_skills_state
                ON cognitive_skills(state, capability);
            """
        )

    @staticmethod
    def _validate_version(version: str) -> str:
        value = version.strip()
        if not value or len(value) > 80 or any(ch.isspace() for ch in value):
            raise ValueError("invalid skill version")
        return value

    def register_donor_skill(
        self,
        registrar_token: str,
        *,
        skill_id: str,
        version: str,
        capability: str,
        donor: dict[str, Any],
        now: int | None = None,
    ) -> SkillRecord:
        principal = self.identity.verify(registrar_token, required_scope="skill:register", now=now)
        if not skill_id.strip() or not capability.strip():
            raise ValueError("skill_id and capability are required")
        version = self._validate_version(version)
        lab = evaluate_donor(donor, {})
        if lab.decision is Decision.REJECTED:
            raise SkillError(f"donor rejected: {lab.reason}")
        ts = float(time.time() if now is None else now)
        evidence = {name: False for name in REQUIRED_EVIDENCE}
        try:
            self.store.conn.execute(
                """
                INSERT INTO cognitive_skills(
                    skill_id, version, capability, donor_id, donor_json, evidence_json,
                    state, authority, executable, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    skill_id.strip(),
                    version,
                    capability.strip(),
                    str(donor.get("id")),
                    json.dumps(donor, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    json.dumps(evidence, sort_keys=True),
                    "QUARANTINED",
                    "none",
                    0,
                    ts,
                    ts,
                ),
            )
        except Exception as exc:
            raise SkillError("skill version already exists or could not be registered") from exc
        self.audit.append(
            actor=principal.subject,
            action="skill_registered",
            payload={"skill_id": skill_id.strip(), "version": version, "donor_id": str(donor.get("id"))},
        )
        return self.get(skill_id, version)

    def get(self, skill_id: str, version: str) -> SkillRecord:
        row = self.store.conn.execute(
            "SELECT * FROM cognitive_skills WHERE skill_id=? AND version=?",
            (skill_id, version),
        ).fetchone()
        if not row:
            raise SkillError("skill not found")
        return SkillRecord(
            skill_id=str(row["skill_id"]),
            version=str(row["version"]),
            capability=str(row["capability"]),
            donor_id=str(row["donor_id"]),
            state=str(row["state"]),
            authority=str(row["authority"]),
            executable=bool(row["executable"]),
            evidence=dict(json.loads(row["evidence_json"])),
            donor=dict(json.loads(row["donor_json"])),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
        )

    def record_evidence(
        self,
        validator_token: str,
        *,
        skill_id: str,
        version: str,
        evidence_name: str,
        passed: bool,
        now: int | None = None,
    ) -> SkillRecord:
        principal = self.identity.verify(validator_token, required_scope="skill:validate", now=now)
        if evidence_name not in REQUIRED_EVIDENCE:
            raise SkillError("unknown laboratory evidence")
        record = self.get(skill_id, version)
        if record.state != "QUARANTINED":
            raise SkillError("evidence can only be changed while quarantined")
        evidence = dict(record.evidence)
        evidence[evidence_name] = bool(passed)
        ts = float(time.time() if now is None else now)
        self.store.conn.execute(
            "UPDATE cognitive_skills SET evidence_json=?, updated_at=? WHERE skill_id=? AND version=?",
            (json.dumps(evidence, sort_keys=True), ts, skill_id, version),
        )
        self.audit.append(
            actor=principal.subject,
            action="skill_evidence_recorded",
            payload={"skill_id": skill_id, "version": version, "evidence": evidence_name, "passed": bool(passed)},
        )
        return self.get(skill_id, version)

    def approve(self, approver_token: str, *, skill_id: str, version: str, now: int | None = None) -> SkillRecord:
        principal = self.identity.verify(approver_token, required_scope="skill:approve", now=now)
        record = self.get(skill_id, version)
        if record.state != "QUARANTINED":
            raise SkillError("only quarantined skills can be approved")
        lab = evaluate_donor(record.donor, record.evidence)
        if lab.decision is not Decision.APPROVED:
            raise SkillError(f"skill laboratory gate failed: {lab.reason}; missing={lab.missing_evidence}")
        if lab.authority != "adapter-only" or lab.executable:
            raise SkillError("laboratory attempted to grant forbidden authority")
        ts = float(time.time() if now is None else now)
        self.store.conn.execute(
            """
            UPDATE cognitive_skills
            SET state='APPROVED', authority='adapter-only', executable=0, updated_at=?
            WHERE skill_id=? AND version=?
            """,
            (ts, skill_id, version),
        )
        self.audit.append(
            actor=principal.subject,
            action="skill_approved",
            payload={"skill_id": skill_id, "version": version, "authority": "adapter-only", "executable": False},
        )
        return self.get(skill_id, version)

    def suspend(self, operator_token: str, *, skill_id: str, version: str, reason: str, now: int | None = None) -> SkillRecord:
        principal = self.identity.verify(operator_token, required_scope="skill:suspend", now=now)
        record = self.get(skill_id, version)
        if record.state != "APPROVED":
            raise SkillError("only approved skills can be suspended")
        ts = float(time.time() if now is None else now)
        self.store.conn.execute(
            "UPDATE cognitive_skills SET state='SUSPENDED', authority='none', executable=0, updated_at=? WHERE skill_id=? AND version=?",
            (ts, skill_id, version),
        )
        self.audit.append(
            actor=principal.subject,
            action="skill_suspended",
            payload={"skill_id": skill_id, "version": version, "reason": reason},
        )
        return self.get(skill_id, version)

    def retire(self, operator_token: str, *, skill_id: str, version: str, reason: str, now: int | None = None) -> SkillRecord:
        principal = self.identity.verify(operator_token, required_scope="skill:suspend", now=now)
        record = self.get(skill_id, version)
        if record.state not in {"QUARANTINED", "APPROVED", "SUSPENDED"}:
            raise SkillError("skill cannot be retired from current state")
        ts = float(time.time() if now is None else now)
        self.store.conn.execute(
            "UPDATE cognitive_skills SET state='RETIRED', authority='none', executable=0, updated_at=? WHERE skill_id=? AND version=?",
            (ts, skill_id, version),
        )
        self.audit.append(
            actor=principal.subject,
            action="skill_retired",
            payload={"skill_id": skill_id, "version": version, "reason": reason},
        )
        return self.get(skill_id, version)

    def resolve_approved(self, skill_id: str, version: str | None = None) -> SkillRecord:
        if version is None:
            row = self.store.conn.execute(
                "SELECT version FROM cognitive_skills WHERE skill_id=? AND state='APPROVED' ORDER BY updated_at DESC LIMIT 1",
                (skill_id,),
            ).fetchone()
            if not row:
                raise SkillError("no approved skill version")
            version = str(row["version"])
        record = self.get(skill_id, version)
        if record.state != "APPROVED" or record.authority != "adapter-only" or record.executable:
            raise SkillError("skill is not eligible for cognitive adapter use")
        return record
