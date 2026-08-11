# ADR-0002 — Fundação Soberana Executável

**Status:** Accepted  
**Data:** 11/08/2026

## Contexto

A Fase 1 transformou a especificação em Constituição, contratos, máquinas de estado,
políticas e critérios de aceite. A Fase 2 precisa tornar executável a fronteira soberana
sem conceder autoridade aos 44 doadores OSS ainda em laboratório.

## Decisão

1. O estado operacional inicial usa SQLite da biblioteca padrão Python, com WAL,
   `synchronous=FULL` e chaves estrangeiras ativadas.
2. O motor durável implementa fila persistente, prioridade, idempotência, leases,
   recuperação de leases expirados, retry limitado e continuidade de tarefas independentes.
3. O `PolicyGuard` é código próprio e fail-closed. Ele valida o hash da Constituição
   contra a evidência da Fase 1 antes de autorizar ação.
4. O PolicyGuard executa as regras soberanas essenciais sem depender de IA ou doador externo.
   OPA permanece doador candidato; sua futura integração será por Adapter e exige laboratório.
5. Identidades internas são tokens de curta duração autenticados por HMAC-SHA256, com
   scopes explícitos e verificação de expiração/assinatura.
6. Auditoria material é append-only por interface e encadeada por SHA-256. A cadeia pode
   detectar adulteração persistida.
7. `MISSION_PROVEN` é calculado e assinado por HMAC-SHA256 pelo Motor de Aceite; o motor
   durável só aceita conclusão com prova válida para a mesma missão. Booleanos fornecidos
   por agentes/Workers não têm autoridade.
8. O PolicyGuard só aceita entrada operacional pela rota autenticada `evaluate_token`; a
   avaliação de um Principal já verificado é interna.
9. Nenhuma peça OSS recebe execução direta ou autoridade nesta fase.

## Consequências

- A Fundação funciona sem IA externa e sem dependências Python adicionais.
- Reinício do processo não perde missões/tarefas e leases expirados são retomáveis.
- Ações financeiras, destrutivas, fora de escopo, que desativem segurança ou violem a
  fronteira OSS são bloqueadas ou encaminhadas ao gate humano.
- SQLite é uma decisão inicial substituível. Escala distribuída será tratada por Adapter/ADR
  posterior sem mudar os contratos soberanos.
- Checkpoint/rollback físico de sistemas protegidos e Executor Privilegiado pertencem à Fase 3.
