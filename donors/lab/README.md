# Laboratório de doadores OSS

Esta camada extrai a capacidade declarada das peças e impede que presença no
almoxarifado seja confundida com aprovação operacional.

Estados:

- `rejected`: origem/coleta obrigatória inválida;
- `quarantined`: peça preservada, mas faltam evidências;
- `approved`: todos os portões passaram; somente integração por Adapter.

Mesmo aprovada, uma peça recebe `authority=adapter-only` e
`executable=false`. Execução exige decisão separada do Núcleo Soberano,
PolicyGuard, escopo de missão, checkpoint e validação MISSION_PROVEN.

Portões obrigatórios: integridade da origem, auditoria de licença, varredura de
segurança, teste funcional, teste de isolamento e teste de rollback.
