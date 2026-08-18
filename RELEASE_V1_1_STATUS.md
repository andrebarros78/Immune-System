# Sistema Imunológico V1.1.0 — Sovereign Brain Fortress

**Estado: V1_1_CONSOLIDATED_PROVEN**

Base preservada: `v1.0.1`.

Escopo novo: `SOVEREIGN_BRAIN_FORTRESS_V1_CLOSED_LAB`.

Tag alvo imutável: `v1.1.0`.

## Conteúdo da release

- sete anéis concêntricos de contenção;
- Sovereign Core sem rede, subprocesso, adapters, provider credentials, HTTP panel ou control-plane;
- Execution Broker externo;
- Provider Proxy externo com DLP e quarentena de prompt injection;
- Control Plane e Presentation fora do Core;
- Policy Authority com facts derivados e capability one-shot ligada a missão/alvo/ação/parâmetros/checkpoint;
- Gateway egress sem booleans de autorização fornecidos pelo chamador;
- risk/checkpoint/recovery derivados da fronteira do adapter;
- Memory Vault com selo independente;
- Audit Ledger com seal externo;
- Root Manifest assinado, generation anti-rollback e boot fail-closed;
- runtime oficial atesta Root of Trust antes de abrir/criar SQLite;
- fila global única para Provider live em CI, evitando autoindução de rate-limit.

## Cadeia de aceite

- `MISSION_PROVEN`: preservado;
- `DIGITAL_TWIN_PROVEN`: preservado;
- `BRAIN_FORTRESS_PROVEN`: comprovado;
- GitHub Fortress main run `32135967148`: success;
- GitHub Mission Integral main run `32135967165`: success;
- GitHub Fortress release-document run `32136856684`: success.

## Regra da tag

A tag anotada `v1.1.0` somente pode ser criada no commit que contém este estado `V1_1_CONSOLIDATED_PROVEN` após o workflow `BRAIN_FORTRESS_PROVEN - Seven Ring Isolated Validation` terminar `success` nesse mesmo SHA.

A tag é imutável. `v1.0.0` e `v1.0.1` não serão movidas.

## Fronteira de implantação

A release prova a arquitetura e sua operação integral em closed-lab/CI sem sistemas reais anexados. Qualquer implantação física exige Root of Trust hardware-backed e prova própria do host conforme `runbooks/BRAIN-FORTRESS-DEPLOYMENT.md`.
