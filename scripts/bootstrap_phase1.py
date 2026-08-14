#!/usr/bin/env python3
"""Generate Phase 1 sovereign specification, contracts, policies and tests.

Source basis: SISTEMA_IMUNOLOGICO_ESPECIFICACAO_DETALHADA v1.0 (11/08/2026).
This generator only materializes governance/contract artifacts. It does not
integrate or execute OSS donor code.
"""
from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parents[1]


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.rstrip() + "\n", encoding="utf-8")


def write_json(path: str, value: object) -> None:
    write(path, json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


SOURCE_SHA256 = "d912a3b7410be88579b33be4fb266c72ca7dc15fc5550206747b7b7eef3327f5"
SOURCE_BYTES = 40412

write_json(
    "specification/SOURCE_MANIFEST.json",
    {
        "schema": 1,
        "source_name": "SISTEMA_IMUNOLOGICO_ESPECIFICACAO_DETALHADA(2).md",
        "title": "SISTEMA IMUNOLÓGICO — Especificação conceitual e funcional detalhada",
        "version": "1.0",
        "date": "2026-08-11",
        "sha256": SOURCE_SHA256,
        "bytes": SOURCE_BYTES,
        "attestation": "Hash calculado sobre o arquivo fornecido pelo responsável do produto no momento da execução da Fase 1.",
        "precedence": [
            "decisões explícitas mais recentes do responsável do produto",
            "ADRs aprovadas posteriores",
            "contratos versionados",
            "evidência operacional",
            "documentação",
        ],
    },
)

write(
    "specification/SISTEMA_IMUNOLOGICO_SPEC_V1.md",
    dedent(
        f"""
        # Sistema Imunológico — Baseline normativa executável v1.0

        **Fonte canônica:** `SISTEMA_IMUNOLOGICO_ESPECIFICACAO_DETALHADA(2).md`  
        **SHA-256 da fonte:** `{SOURCE_SHA256}`  
        **Data:** 11/08/2026

        Este arquivo é a baseline normativa usada pelos contratos executáveis da Fase 1.
        Ele não reduz a especificação detalhada: requisitos e decisões devem ser rastreados
        ao documento fonte pelo `specification/SOURCE_MANIFEST.json`.

        ## Definição oficial

        O Sistema Imunológico é um produto independente e tecnologicamente adaptável,
        com autonomia operacional ampla dentro de sua missão. Descobre ambientes,
        aprende tecnologias desconhecidas por fontes verificáveis, cria as capacidades
        necessárias, diagnostica e corrige falhas, valida os resultados e continua
        trabalhando para manter cada sistema autorizado saudável e operacional.

        ## Princípios normativos

        1. **Independência:** sistemas protegidos entram por contratos, conectores e adapters.
        2. **Núcleo soberano:** autoridade, permissão, isolamento, aplicação, rollback e aceite permanecem no núcleo próprio.
        3. **Autonomia governada:** autonomia existe somente dentro de missão, escopo, políticas, custo e risco autorizados.
        4. **Prova antes da conclusão:** compilar, iniciar ou produzir saída parcial não prova correção.
        5. **Reversibilidade:** mudanças materiais exigem recuperação verificável proporcional ao risco.
        6. **Isolamento:** sistema, missão, incidente, tentativa e Worker possuem fronteiras independentes.
        7. **Aprendizagem controlada:** conhecimento só é promovido após evidência, teste, versionamento e possibilidade de reversão.
        8. **Tecnologia substituível:** IA, bancos, observabilidade e peças OSS são subordinados a contratos estáveis.
        9. **Menor caminho completo:** reutilizar tecnologia comprovada e construir somente lacunas.
        10. **Verdade operacional:** fato, hipótese, decisão, estimativa e pendência não podem ser confundidos.

        ## Separação de autoridade

        Pensar, autorizar, executar e validar são funções separadas. IA e Skills podem
        propor, mas não autorizam nem executam por conta própria. PolicyGuard autoriza
        dentro da política; Workers executam no escopo; validadores produzem evidência;
        o Motor de Aceite só emite prova quando os contratos forem satisfeitos.

        ## Regra Open Source Only

        Decisão explícita posterior do responsável do produto: componentes doadores do
        Sistema Imunológico devem ser **somente Open Source**, com licença explícita,
        origem pinada e auditável. Software proprietário, source-available não-OSS ou
        dependência que exija serviço proprietário não pode ser promovido como doador.

        ## Loop operacional

        OBSERVAR → ENTENDER → DECIDIR → DELEGAR → ACOMPANHAR → VALIDAR → APRENDER → CONTINUAR.

        Para correção técnica: INSPECIONAR → REPRODUZIR → COLETAR EVIDÊNCIA → ISOLAR →
        IDENTIFICAR CAUSA → CORRIGIR → TESTAR CORREÇÃO → TESTAR REGRESSÕES → TESTAR
        INTEGRAÇÃO → TESTAR RECUPERAÇÃO → AUDITAR → SALVAR CHECKPOINT → PROCURAR NOVA FALHA → CONTINUAR.

        ## MISSION_PROVEN

        `MISSION_PROVEN` só pode existir para escopo explícito quando resultado observável,
        testes relevantes, regressão, recuperação e segurança proporcionais ao risco,
        evidências e ausência de bloqueio crítico estiverem comprovados. Pendências
        opcionais devem estar separadas do escopo aceito.

        ## Intervenção humana por exceção

        Escalar somente para gasto/contratação, criação de conta, credencial pessoal
        inexistente, MFA/CAPTCHA/confirmação física, compromisso jurídico, comunicação
        externa, regra de negócio, ação irreversível sem recuperação ou bloqueio real
        após rotas técnicas distintas permitidas.
        """
    ),
)

write(
    "constitution/IMUNE-DNA-001.md",
    dedent(
        """
        # IMUNE-DNA-001 — Constituição Soberana do Sistema Imunológico

        **Versão:** 1.0.0  
        **Estado:** normativa e obrigatória  
        **Herança:** obrigatória; descendentes podem restringir, nunca relaxar.

        ## 1. Missão soberana

        Preservar continuamente a saúde dos sistemas explicitamente autorizados por meio
        de observação, diagnóstico causal, correção reversível, teste, recuperação,
        evidência, auditoria e aprendizagem controlada.

        ## 2. Limite de autoridade

        Toda autoridade nasce da missão autorizada e é intersectada com a política do
        núcleo. Agente, Skill, Worker, adapter, modelo ou doador não pode ampliar o
        próprio escopo, conceder permissão a si mesmo ou alterar regra de negócio.

        ## 3. Open Source Only

        Componentes doadores devem ser Open Source com licença explícita verificável.
        Source-available não-OSS, freeware proprietário ou dependência obrigatória de
        serviço proprietário não satisfaz esta Constituição.

        ## 4. Fail-closed

        Constituição ausente, ilegível, incompatível, hash divergente ou herança não
        comprovada coloca o sistema em modo seguro: observar, preservar evidência e
        diagnosticar. Aplicação, promoção, execução material e declaração de prova ficam bloqueadas.

        ## 5. Separação de funções

        Pensar, autorizar, executar e validar são capacidades independentes. Quem cria
        uma correção não pode ser seu único aprovador. Nenhum agente pode emitir
        `MISSION_PROVEN`; o estado é computado pelo Motor de Aceite.

        ## 6. Política financeira absoluta

        Nova compra, assinatura, contratação, serviço pago, trial com risco de cobrança,
        licença comercial, pagamento ou cartão exige autorização humana explícita.

        ## 7. Segurança e reversibilidade

        Não desativar UAC, firewall, antivírus, autenticação, MFA ou controles de
        segurança para contornar impedimentos. Mudança material exige checkpoint,
        backup, snapshot, branch, transação ou outra recuperação comprovável conforme risco.

        ## 8. Loop Engineering obrigatório

        INSPECIONAR → REPRODUZIR → COLETAR EVIDÊNCIA → ISOLAR → IDENTIFICAR CAUSA RAIZ →
        CORRIGIR → TESTAR CORREÇÃO → TESTAR REGRESSÕES → TESTAR INTEGRAÇÃO → TESTAR
        PONTA A PONTA → TESTAR RECUPERAÇÃO → ESTRESSAR → AUDITAR → SALVAR CHECKPOINT →
        PROCURAR NOVA FALHA → CONTINUAR.

        Tentativa falha deve gerar evidência ou hipótese tecnicamente diferente. Repetição
        equivalente sem nova evidência é violação constitucional.

        ## 9. Donor boundary

        Presença no almoxarifado não concede autoridade. Doador deve passar por origem,
        licença, hash, segurança, laboratório, isolamento, rollback e adapter. Mesmo
        aprovado, continua subordinado ao PolicyGuard.

        ## 10. Evidência e verdade operacional

        Correção sem teste é não comprovada. Build verde isolado não equivale a resultado
        operacional. Toda ação material deve ser reconstruível por identidade, missão,
        política, estado anterior, execução, resultado, testes, checkpoint e estado posterior.

        ## 11. Continuidade

        Estado crítico deve ser durável fora da conversa. Reinício deve retomar do último
        checkpoint válido, impedir duplicação e confirmar saúde antes de declarar recuperação.

        ## 12. Exceções humanas

        Escalar apenas quando houver limite humano real: custo/contratação, conta nova,
        credencial pessoal inexistente, MFA/CAPTCHA, compromisso jurídico, comunicação
        externa, regra de negócio ou ação irreversível sem recuperação segura.

        ## 13. MISSION_PROVEN

        É impossível declarar `MISSION_PROVEN` sem escopo explícito, resultado observável,
        testes relevantes, regressão/recuperação/segurança proporcionais ao risco,
        evidências preservadas, ausência de bloqueio crítico e auditoria final independente.
        """
    ),
)

DRAFT = "https://json-schema.org/draft/2020-12/schema"

def s_string(**extra):
    return {"type": "string", **extra}

def s_bool():
    return {"type": "boolean"}

def s_arr(items=None, min_items=0):
    return {"type": "array", "items": items or {"type": "string"}, "minItems": min_items}

def schema(name: str, title: str, required: list[str], properties: dict) -> dict:
    return {
        "$schema": DRAFT,
        "$id": f"https://immune-system.local/contracts/{name}.schema.json",
        "title": title,
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }

schemas = {
    "system": schema(
        "system", "Protected System Contract",
        ["id", "owner", "objective", "essential_functions", "health_indicators", "allowed_actions", "prohibited_actions", "acceptance_tests", "human_exception_channel"],
        {
            "id": s_string(minLength=1), "owner": s_string(minLength=1), "objective": s_string(minLength=1),
            "essential_functions": s_arr(min_items=1), "environments": s_arr(), "health_indicators": s_arr(min_items=1),
            "interfaces": s_arr(), "allowed_actions": s_arr(), "prohibited_actions": s_arr(), "maintenance_policy": s_string(),
            "backups_and_rollback": s_arr(), "sensitive_data": s_arr(), "dependencies": s_arr(),
            "acceptance_tests": s_arr(min_items=1), "human_exception_channel": s_string(minLength=1), "authorized": s_bool(),
        },
    ),
    "mission": schema(
        "mission", "Mission Contract",
        ["id", "system_id", "objective", "authorized_by", "authorized_at", "scope", "budget_limit", "risk_limit", "status"],
        {
            "id": s_string(minLength=1), "system_id": s_string(minLength=1), "objective": s_string(minLength=1),
            "authorized_by": s_string(minLength=1), "authorized_at": s_string(format="date-time"), "scope": s_arr(min_items=1),
            "budget_limit": {"type": "number", "minimum": 0}, "risk_limit": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "authorized": s_bool(), "status": {"type": "string", "enum": ["CREATED", "AUTHORIZED", "DISCOVERING", "RUNNING", "DEGRADED", "BLOCKED", "WAITING_HUMAN", "CONTAINED", "VALIDATING", "COMPLETED", "FAILED_SAFE", "CANCELLED"]},
            "constraints": s_arr(), "deadline": {"type": ["string", "null"], "format": "date-time"},
        },
    ),
    "incident": schema(
        "incident", "Incident Contract",
        ["id", "system_id", "severity", "symptoms", "evidence_refs", "hypotheses", "attempt_refs", "status"],
        {
            "id": s_string(minLength=1), "system_id": s_string(minLength=1), "component": s_string(),
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]}, "priority": {"type": "integer", "minimum": 0},
            "started_at": s_string(format="date-time"), "updated_at": s_string(format="date-time"), "symptoms": s_arr(min_items=1),
            "impact": s_string(), "evidence_refs": s_arr(), "hypotheses": s_arr(), "attempt_refs": s_arr(), "action_refs": s_arr(), "checkpoint_refs": s_arr(),
            "test_results": s_arr(), "residual_risk": s_string(), "human_owner": {"type": ["string", "null"]},
            "status": {"type": "string", "enum": ["DETECTED", "CONFIRMED", "TRIAGED", "INVESTIGATING", "CAUSE_IDENTIFIED", "FIX_PLANNED", "FIX_TESTING", "FIX_APPROVED", "APPLYING", "VALIDATING", "MONITORING_RECOVERY", "RESOLVED", "ROLLED_BACK", "CONTAINED", "ESCALATED", "CLOSED_WITH_RISK"]},
        },
    ),
    "task": schema(
        "task", "Worker Task Contract",
        ["id", "mission_id", "objective", "target", "permissions", "timeout_seconds", "expected_output", "required_evidence", "failure_behavior"],
        {
            "id": s_string(minLength=1), "mission_id": s_string(minLength=1), "incident_id": {"type": ["string", "null"]},
            "objective": s_string(minLength=1), "target": s_string(minLength=1), "allowed_inputs": s_arr(), "tools": s_arr(), "permissions": s_arr(),
            "timeout_seconds": {"type": "integer", "minimum": 1}, "resource_limits": {"type": "object"}, "cancel_action": s_string(),
            "expected_output": s_string(minLength=1), "required_evidence": s_arr(min_items=1), "failure_behavior": s_string(minLength=1),
        },
    ),
    "worker": schema(
        "worker", "Worker Manifest",
        ["id", "kind", "capabilities", "authority", "minimum_privilege", "cancelable", "evidence_required"],
        {
            "id": s_string(minLength=1), "kind": s_string(minLength=1), "capabilities": s_arr(min_items=1), "authority": {"type": "string", "enum": ["none", "task-scoped", "privileged-ephemeral"]},
            "minimum_privilege": s_bool(), "cancelable": s_bool(), "timeout_supported": s_bool(), "evidence_required": s_bool(), "credential_retention": {"type": "string", "enum": ["none", "task-only"]},
        },
    ),
    "evidence": schema(
        "evidence", "Evidence Contract",
        ["id", "origin", "observed_at", "method", "environment", "expected", "observed", "integrity_sha256", "requirement_refs"],
        {
            "id": s_string(minLength=1), "origin": s_string(minLength=1), "observed_at": s_string(format="date-time"), "method": s_string(minLength=1),
            "environment": s_string(minLength=1), "artifact_ref": {"type": ["string", "null"]}, "expected": s_string(minLength=1), "observed": s_string(minLength=1),
            "integrity_sha256": s_string(pattern="^[a-fA-F0-9]{64}$"), "requirement_refs": s_arr(min_items=1), "sensitive_data_redacted": s_bool(),
        },
    ),
    "checkpoint": schema(
        "checkpoint", "Checkpoint Contract",
        ["id", "mission_id", "created_at", "baseline_ref", "state_hash", "recovery_procedure", "recovery_verified"],
        {
            "id": s_string(minLength=1), "mission_id": s_string(minLength=1), "created_at": s_string(format="date-time"), "baseline_ref": s_string(minLength=1),
            "state_hash": s_string(pattern="^[a-fA-F0-9]{64}$"), "recovery_procedure": s_string(minLength=1), "recovery_verified": s_bool(), "artifact_refs": s_arr(),
        },
    ),
    "policy-decision": schema(
        "policy-decision", "Policy Decision Contract",
        ["id", "mission_id", "decision", "policy_version", "reasons", "decided_at"],
        {
            "id": s_string(minLength=1), "mission_id": s_string(minLength=1), "decision": {"type": "string", "enum": ["PERMITIR", "PERMITIR_COM_RESTRIÇÕES", "EXIGIR_CHECKPOINT", "EXIGIR_APROVAÇÃO_HUMANA", "BLOQUEAR", "CONTER_E_ESCALAR"]},
            "policy_version": s_string(minLength=1), "reasons": s_arr(min_items=1), "restrictions": s_arr(), "decided_at": s_string(format="date-time"),
        },
    ),
    "donor-component": schema(
        "donor-component", "OSS Donor Component Contract",
        ["id", "origin", "resolved_commit", "license_spdx", "license_verified", "artifact_hash", "state", "authority"],
        {
            "id": s_string(minLength=1), "origin": s_string(minLength=1), "resolved_commit": s_string(pattern="^[a-fA-F0-9]{40}$"), "license_spdx": s_string(minLength=1),
            "open_source": s_bool(), "license_verified": s_bool(), "artifact_hash": s_string(pattern="^[a-fA-F0-9]{64}$"),
            "state": {"type": "string", "enum": ["registered", "metadata_verified", "artifact_collected", "security_scanned", "laboratory_approved", "integration_approved", "rejected", "retired"]},
            "authority": {"type": "string", "enum": ["none", "adapter-only"]}, "adapter_ref": {"type": ["string", "null"]},
        },
    ),
    "human-exception": schema(
        "human-exception", "Human Exception Contract",
        ["id", "mission_id", "reason_type", "required_action", "reason", "continuation_after_action", "status"],
        {
            "id": s_string(minLength=1), "mission_id": s_string(minLength=1), "reason_type": {"type": "string", "enum": ["cost", "new_account", "personal_credential", "mfa_captcha_physical", "legal_commitment", "external_communication", "business_rule", "irreversible_without_recovery", "persistent_external_blocker"]},
            "required_action": s_string(minLength=1), "reason": s_string(minLength=1), "consequence": s_string(), "continuation_after_action": s_string(minLength=1),
            "status": {"type": "string", "enum": ["OPEN", "SATISFIED", "CANCELLED"]},
        },
    ),
}

for name, value in schemas.items():
    write_json(f"contracts/{name}.schema.json", value)

write(
    "state-machines/mission.yaml",
    dedent(
        """
        schema: 1
        name: Mission
        initial: CREATED
        terminal: [COMPLETED, FAILED_SAFE, CANCELLED]
        states: [CREATED, AUTHORIZED, DISCOVERING, RUNNING, DEGRADED, BLOCKED, WAITING_HUMAN, CONTAINED, VALIDATING, COMPLETED, FAILED_SAFE, CANCELLED]
        transitions:
          - {from: CREATED, to: AUTHORIZED, guard: mission_contract_valid}
          - {from: AUTHORIZED, to: DISCOVERING, guard: system_authorized}
          - {from: DISCOVERING, to: RUNNING, guard: baseline_established}
          - {from: RUNNING, to: DEGRADED, guard: essential_function_preserved_with_degradation}
          - {from: RUNNING, to: BLOCKED, guard: localized_blocker}
          - {from: RUNNING, to: CONTAINED, guard: risk_isolated}
          - {from: RUNNING, to: VALIDATING, guard: observable_result_candidate}
          - {from: BLOCKED, to: WAITING_HUMAN, guard: human_exception_contract_valid}
          - {from: WAITING_HUMAN, to: RUNNING, guard: human_blocker_removed}
          - {from: CONTAINED, to: RUNNING, guard: containment_exit_safe}
          - {from: VALIDATING, to: COMPLETED, guard: mission_proven}
          - {from: VALIDATING, to: RUNNING, guard: validation_failed_and_recovery_safe}
          - {from: RUNNING, to: FAILED_SAFE, guard: cannot_complete_but_environment_preserved}
          - {from: RUNNING, to: CANCELLED, guard: competent_authority_cancelled}
        invariant: COMPLETED requires MISSION_PROVEN
        """
    ),
)

write(
    "state-machines/incident.yaml",
    dedent(
        """
        schema: 1
        name: Incident
        initial: DETECTED
        states: [DETECTED, CONFIRMED, TRIAGED, INVESTIGATING, CAUSE_IDENTIFIED, FIX_PLANNED, FIX_TESTING, FIX_APPROVED, APPLYING, VALIDATING, MONITORING_RECOVERY, RESOLVED, ROLLED_BACK, CONTAINED, ESCALATED, CLOSED_WITH_RISK]
        transitions:
          - {from: DETECTED, to: CONFIRMED, guard: anomaly_confirmed}
          - {from: CONFIRMED, to: TRIAGED, guard: impact_and_scope_known}
          - {from: TRIAGED, to: INVESTIGATING, guard: evidence_plan_defined}
          - {from: INVESTIGATING, to: CAUSE_IDENTIFIED, guard: causal_evidence_sufficient}
          - {from: CAUSE_IDENTIFIED, to: FIX_PLANNED, guard: correction_and_rollback_defined}
          - {from: FIX_PLANNED, to: FIX_TESTING, guard: checkpoint_valid}
          - {from: FIX_TESTING, to: FIX_APPROVED, guard: isolated_tests_passed}
          - {from: FIX_TESTING, to: INVESTIGATING, guard: candidate_rejected}
          - {from: FIX_APPROVED, to: APPLYING, guard: policy_guard_permits}
          - {from: APPLYING, to: VALIDATING, guard: action_completed}
          - {from: VALIDATING, to: MONITORING_RECOVERY, guard: primary_result_passed}
          - {from: VALIDATING, to: ROLLED_BACK, guard: regression_or_failure_detected}
          - {from: ROLLED_BACK, to: INVESTIGATING, guard: rollback_verified}
          - {from: MONITORING_RECOVERY, to: RESOLVED, guard: stability_window_passed}
          - {from: INVESTIGATING, to: CONTAINED, guard: risk_requires_containment}
          - {from: CONTAINED, to: ESCALATED, guard: human_exception_required}
          - {from: MONITORING_RECOVERY, to: CLOSED_WITH_RISK, guard: accepted_residual_risk_explicit}
        """
    ),
)

write(
    "state-machines/attempt.yaml",
    dedent(
        """
        schema: 1
        name: Attempt
        source_note: "Implementation decision operationalizing specification section 9.3; states were not enumerated in the source document."
        initial: CREATED
        terminal: [SUCCEEDED, FAILED, ABORTED]
        states: [CREATED, RUNNING, SUCCEEDED, FAILED, ABORTED]
        transitions:
          - {from: CREATED, to: RUNNING, guard: hypothesis_and_discriminating_test_recorded}
          - {from: RUNNING, to: SUCCEEDED, guard: evidence_supports_expected_result}
          - {from: RUNNING, to: FAILED, guard: evidence_rejects_or_fails_attempt}
          - {from: RUNNING, to: ABORTED, guard: risk_or_timeout_requires_stop}
        invariants:
          - equivalent_retry_requires_new_evidence
          - each_retry_requires_technical_delta
          - failure_must_record_learning
        """
    ),
)

policies = {
    "authority.rego": '''package immune.authority

default decision := "BLOQUEAR"

decision := "PERMITIR" if {
  input.mission_authorized == true
  input.system_authorized == true
  input.requester_authorized == true
  input.scope_ok == true
  not input.restrictions_required
}

decision := "PERMITIR_COM_RESTRIÇÕES" if {
  input.mission_authorized == true
  input.system_authorized == true
  input.requester_authorized == true
  input.scope_ok == true
  input.restrictions_required == true
}
''',
    "financial.rego": '''package immune.financial

default decision := "PERMITIR"

decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.new_cost == true }
decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.purchase == true }
decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.subscription == true }
decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.trial_with_billing_risk == true }
decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.commercial_license == true }
''',
    "destructive-actions.rego": '''package immune.destructive

default decision := "PERMITIR"

decision := "EXIGIR_CHECKPOINT" if {
  input.material_change == true
  input.checkpoint_valid != true
}

decision := "EXIGIR_APROVAÇÃO_HUMANA" if {
  input.irreversible == true
  input.recovery_verified != true
}

decision := "BLOQUEAR" if { input.disables_security_control == true }
''',
    "checkpoint.rego": '''package immune.checkpoint

default decision := "PERMITIR"

decision := "EXIGIR_CHECKPOINT" if {
  input.material_change == true
  input.checkpoint_valid != true
}

decision := "BLOQUEAR" if {
  input.checkpoint_required == true
  input.recovery_procedure_defined != true
}
''',
    "secrets.rego": '''package immune.secrets

default decision := "PERMITIR"

decision := "BLOQUEAR" if { input.exposes_secret == true }
decision := "BLOQUEAR" if { input.logs_plaintext_secret == true }
decision := "BLOQUEAR" if { input.prompt_contains_unredacted_secret == true }
''',
    "donor-oss.rego": '''package immune.donor

default decision := "BLOQUEAR"

decision := "PERMITIR_COM_RESTRIÇÕES" if {
  input.open_source == true
  input.license_verified == true
  input.origin_pinned == true
  input.artifact_hash_verified == true
  input.security_scanned == true
  input.laboratory_approved == true
  input.authority == "adapter-only"
}
''',
    "mission-proven.rego": '''package immune.mission

default mission_proven := false

mission_proven if {
  input.scope_explicit == true
  input.observable_result_achieved == true
  input.relevant_tests_passed == true
  input.regression_validated == true
  input.recovery_validated == true
  input.security_validated == true
  input.evidence_preserved == true
  input.no_critical_blocker == true
  input.independent_audit_passed == true
}
''',
}
for name, content in policies.items():
    write(f"policies/{name}", content)

write(
    "acceptance/requirements.yaml",
    dedent(
        """
        schema: 1
        source: "SISTEMA_IMUNOLOGICO_ESPECIFICACAO_DETALHADA v1.0 — sections 18 and 19"
        requirements:
          - {id: AC-01, text: "Todos os requisitos funcionais aprovados implementados", critical: true}
          - {id: AC-02, text: "Nenhuma função crítica simulada ou marcada como futura", critical: true}
          - {id: AC-03, text: "Fluxo completo funcionando em sistemas reais autorizados", critical: true}
          - {id: AC-04, text: "Segurança e separação de autoridade comprovadas", critical: true}
          - {id: AC-05, text: "Falha induzida detectada, diagnosticada, corrigida e validada", critical: true}
          - {id: AC-06, text: "Correção defeituosa rejeitada ou revertida", critical: true}
          - {id: AC-07, text: "Reinício e retomada comprovados", critical: true}
          - {id: AC-08, text: "Operação degradada sem IA externa comprovada", critical: true}
          - {id: AC-09, text: "Isolamento entre sistemas e incidentes demonstrado", critical: true}
          - {id: AC-10, text: "Backup e recuperação testados", critical: true}
          - {id: AC-11, text: "Desempenho e endurance atendem metas oficiais", critical: true}
          - {id: AC-12, text: "Skills e Workers respeitam contratos e permissões", critical: true}
          - {id: AC-13, text: "Laboratório OSS bloqueia integração sem evidência", critical: true}
          - {id: AC-14, text: "Painel reflete fielmente estado interno", critical: true}
          - {id: AC-15, text: "Documentação corresponde ao sistema instalado", critical: true}
          - {id: AC-16, text: "Nenhuma falha crítica conhecida relacionada ao escopo", critical: true}
          - {id: AC-17, text: "Evidências rastreáveis e reproduzíveis", critical: true}
        minimum_proof_scenarios:
          - service_stopped_runbook_recovery
          - configuration_root_cause_fix_with_rollback
          - reject_regression_breaking_fix
          - automatic_invalid_deployment_rollback
          - resume_after_restart_without_duplicate_action
          - isolate_blocked_incident_from_other_systems
          - degraded_operation_without_external_ai
          - create_and_lab_approve_skill_for_unknown_technology
          - block_worker_scope_expansion
          - prove_oss_donor_has_no_direct_authority
          - restore_state_from_tested_backup
          - concurrency_without_task_loss
          - detect_no_progress_and_change_strategy
          - human_intervention_only_for_real_exception
          - requirement_action_test_evidence_report
        """
    ),
)

write(
    "acceptance/mission-proven.yaml",
    dedent(
        """
        schema: 1
        name: MISSION_PROVEN
        default: false
        mandatory_gates:
          - scope_explicit
          - observable_result_achieved
          - relevant_tests_passed
          - regression_validated
          - recovery_validated
          - security_validated
          - evidence_preserved
          - no_critical_blocker
          - independent_audit_passed
        rule: "MISSION_PROVEN is computed by the acceptance engine; no agent, Skill, Worker or donor may claim it."
        """
    ),
)

write(
    "adr/ADR-0001-sovereign-architecture.md",
    dedent(
        """
        # ADR-0001 — Arquitetura Soberana e Contratos Executáveis

        **Status:** Accepted  
        **Data:** 11/08/2026

        ## Contexto

        O Sistema Imunológico precisa combinar IA, Workers e componentes OSS sem transferir
        autoridade de missão, segurança, promoção, rollback ou aceite para componentes externos.

        ## Decisão

        1. O núcleo soberano mantém autoridade e coordenação.
        2. PolicyGuard é a fronteira obrigatória entre proposta e ação material.
        3. Pensar, autorizar, executar e validar permanecem separados.
        4. Contratos são JSON Schema versionados e estritos.
        5. Estados de Mission e Incident seguem a especificação v1.0.
        6. A máquina de Attempt é uma decisão de implementação desta ADR para operacionalizar a seção 9.3; a fonte não enumerou estados de Attempt.
        7. Políticas normativas são expressas em Rego, com comportamento fail-closed onde autoridade é requerida.
        8. Doadores são somente Open Source e entram por adapter após laboratório; nunca recebem soberania.
        9. `MISSION_PROVEN` é um cálculo do Motor de Aceite baseado em evidência.
        10. A implementação futura pode substituir motores OSS, mas não estes contratos soberanos sem ADR posterior e testes de compatibilidade.

        ## Consequências

        - Dependências externas permanecem substituíveis.
        - Falhas de política bloqueiam ação, em vez de permitir por omissão.
        - Contratos podem ser validados antes da Fundação Soberana da Fase 2.
        - Mudanças posteriores devem preservar compatibilidade ou declarar migração explícita.
        """
    ),
)

validator_path = ROOT / "tests/phase1/validate_phase1.py"
if not validator_path.is_file():
    raise FileNotFoundError("versioned Phase 1 validator is missing; bootstrap will not synthesize test authority")
print("Phase 1 artifacts materialized.")
