# ADR-0007 — Experiência Operacional sem transferência de autoridade

## Estado
Aceito para a Fase 7.

## Decisão
A experiência operacional é separada da autoridade soberana.

1. `ReadModel` executa somente `SELECT` e deriva o estado exibido do banco soberano.
2. `HEALTHY` exige evidência de sensor recente; ausência ou envelhecimento nunca produz verde.
3. O painel HTTP é somente leitura (`GET`). Escritas pela interface web são rejeitadas.
4. CLI e runbooks não executam comandos de host. Eles autenticam o operador, consultam `PolicyGuard` e enfileiram `operator_command` no `DurableLoopEngine`.
5. Notificações são persistentes, deduplicadas e informativas; não decidem.
6. Exceções humanas exigem uma ação concreta, motivo, consequência e continuação, e são decididas por identidade `human:approve`.
7. Relatórios preservam rastreabilidade requisito → ação/teste → evidência e hash SHA-256.
8. A queda do painel não afeta o Core, pois painel não possui executor, Worker ou autoridade material.

## Consequência
A interface pode ser substituída sem mudar o núcleo. Nenhum estado “verde”, aprovação ou correção nasce da apresentação visual.
