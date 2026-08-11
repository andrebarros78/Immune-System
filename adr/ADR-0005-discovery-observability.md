# ADR-0005 — Descoberta e Observabilidade Soberanas

## Estado
Aceito para a Fase 5.

## Decisão
O Sistema Imunológico mantém modelo próprio e agnóstico de fornecedor para recursos, dependências, sinais, métricas, logs, traces, saúde de sensores e evidências.

Doadores OSS de observabilidade permanecem atrás de `DonorSensorAdapter`. Presença no almoxarifado não concede execução, autoridade nem aprovação. Um Adapter aceita apenas `LabResult` com `decision=approved`, `authority=adapter-only` e `executable=false`.

## Fluxo
`Sensor → DiscoveryEngine → SignalProcessor/AnomalyDetector → ObservabilityStore → Evidence → Cognição`

A cognição continua sem autoridade material. A execução continua exclusiva do caminho PolicyGuard → fila durável → Worker → Executor comprovado nas fases anteriores.

## Regras
1. Falha de um sensor não interrompe os demais.
2. Cada ciclo gera evidência persistida com SHA-256.
3. Inventário possui digest canônico reproduzível.
4. Sinais são normalizados, deduplicados e correlacionados.
5. Métricas usam baseline histórico robusto; anomalias são sinais, não autorização.
6. Health checks são configurados; não existe varredura arbitrária de portas.
7. Logs e traces são estruturados e persistentes.
8. Doadores reais continuam em quarentena até evidência de laboratório.
9. Nenhum componente desta fase executa correções.
10. PHASE5_PROVEN não equivale a MISSION_PROVEN.
