# ADR-0009 — Prova ponta a ponta controlada

**Status:** Accepted

## Contexto

A Fase 9 deve provar o Sistema Imunológico já construído, e não criar uma demonstração paralela. A especificação exige falhas reais controladas, regressão, recuperação, carga, endurance e segurança, incluindo os 15 cenários mínimos de prova.

## Decisão

1. A prova será executada em runner Linux real do GitHub Actions, usando apenas recursos temporários do job: arquivos, bancos SQLite e processos de loopback.
2. Os 15 cenários mínimos da especificação são gates obrigatórios e executáveis.
3. Dois gates adicionais são obrigatórios: segurança fail-closed e endurance CI.
4. A carga progressiva será comprovada em 1, 4, 8, 16 e 32 operações concorrentes, sem perda ou duplicação de tarefas. p50, p95 e p99 serão preservados como evidência.
5. O gate de endurance CI exige no mínimo 2 segundos e 128 ciclos duráveis completos sem perda. Este número é um gate de homologação CI da Fase 9, não uma alegação de disponibilidade 24x7.
6. Runbooks continuam sem executar comandos diretamente. Um novo `OperatorCommandDispatcher` transforma somente comandos já autenticados e aprovados em tarefas fechadas; o operador escolhe um alvo lógico, enquanto o `argv` vem exclusivamente de `RunbookActionRegistry` configurada pela Core.
7. Backup de estado usa a API nativa de backup consistente do SQLite, SHA-256 e `PRAGMA integrity_check`. Restauração é verificada antes e depois da cópia.
8. Nenhum teste pode desligar controles de segurança, acessar serviços externos, modificar sistemas de terceiros ou produzir efeito fora do sandbox do runner.
9. A Fase 9 não emite `MISSION_PROVEN` do produto completo. A Fase 10 ainda precisa instalar Supervisor, operação contínua, backup periódico, atualização segura e automonitoramento.

## Cenários obrigatórios

1. serviço parado detectado e recuperado por runbook autorizado;
2. causa de configuração identificada e corrigida com rollback disponível;
3. correção que quebra regressão rejeitada;
4. implantação inválida revertida automaticamente;
5. missão retomada após reinício sem duplicação;
6. outro sistema continua enquanto um está bloqueado;
7. monitoramento e contenção funcionam sem IA externa;
8. Skill para tecnologia desconhecida passa por quarentena e laboratório;
9. Worker fora do escopo é bloqueado;
10. peça OSS não recebe autoridade direta;
11. estado é recuperado de backup verificado;
12. carga 1/4/8/16/32 sem perda de tarefas;
13. ausência de progresso força estratégia diferente;
14. intervenção humana aparece somente no cenário de exceção testado;
15. relatório liga requisito, ação, teste e evidência.

## Consequências

- A prova da Fase 9 é reproduzível e fail-closed.
- Métricas e hashes passam a fazer parte da evidência da fase.
- Runbook deixa de terminar apenas no enfileiramento e passa a alcançar uma tarefa executável sem entregar `argv` ao operador.
- Backup/restauração ganha uma primitiva real antes da instalação contínua da Fase 10.
- Limitações permanecem explícitas: runner Linux, janela de endurance CI e ausência de instalação 24x7 nesta fase.
