# ADR-0003 — Execução Isolada, Checkpoints e Fronteira Privilegiada

**Status:** Accepted  
**Data:** 11/08/2026

## Contexto

A Fundação Soberana da Fase 2 já fornece identidade autenticada, PolicyGuard,
estado durável, ledger e prova de missão. A Fase 3 precisa permitir ações reais
sem transformar Workers em processos soberanos nem criar atalhos de privilégio.

## Decisão

1. Todo Worker possui `WorkerManifest` com tipos de tarefa, capacidades, autoridade,
   executáveis permitidos, timeout, limite de saída e allowlist de ambiente.
2. Toda execução material é vinculada a um `TaskLease` durável.
3. O diretório de trabalho é derivado de `mission_id/task_id`; o chamador não escolhe
   um `cwd` arbitrário.
4. O Executor Seguro usa `subprocess` com `shell=False`, entrada padrão desabilitada,
   timeout obrigatório, ambiente mínimo e allowlist de executáveis.
5. Mudança material recebe checkpoint antes da execução. Falha restaura o checkpoint
   automaticamente quando a recuperação é aplicável.
6. Checkpoints são snapshots de filesystem com inventário e SHA-256; adulteração
   invalida rollback.
7. Execução privilegiada exige identidade `execute:privileged`, capacidade declarada,
   checkpoint íntegro e grant HMAC de uso único com TTL máximo de 300 segundos,
   vinculado exatamente a missão, tarefa, Worker, ação e checkpoint.
8. O token que autoriza a emissão do grant é externo ao Worker e exige
   `grant:privileged`.
9. O Executor Privilegiado não executa `sudo`, bypass de UAC, autoelevação ou
   desativação de segurança. A identidade privilegiada do sistema operacional,
   quando necessária em fases de integração de host, deverá ser fornecida por
   um serviço/Worker já autorizado pelo SO.
10. Missões inativas (`BLOCKED`, `WAITING_HUMAN`, `CONTAINED`, `FAILED_SAFE`,
    `CANCELLED`, `COMPLETED`) não podem produzir nova execução material.

## Consequências

- Workers continuam substituíveis e sem soberania.
- Um token roubado tem alcance limitado por scope, tarefa, tempo e política.
- Grants privilegiados não são reutilizáveis.
- Uma correção material defeituosa pode voltar ao estado anterior comprovado.
- A fase prova a fronteira de execução; não afirma que todos os adaptadores de
  privilégio específicos de Windows/Linux já existem.
