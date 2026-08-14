# GitHub Provider Isolated Test

## Objetivo

Provar somente a comunicação cognitiva entre o Sistema Imunológico e o provedor GLM/Z.AI, sem conectar o produto a qualquer sistema existente.

## Ambiente

- runner efêmero: `ubuntu-latest` do GitHub Actions;
- workflow: `.github/workflows/provider-live-smoke.yml`;
- environment: `immune-live-test`;
- secret: `IMMUNE_PROVIDER_PRIMARY_API_KEY`;
- configuração: `config/provider-live-test.json`;
- endpoint permitido: `https://api.z.ai/api/paas/v4/chat/completions`;
- nenhum endpoint local, Windows-MCP, WMCP, TUNEL-CORE operacional ou sistema protegido é disponibilizado ao teste.

## Execução

1. O GitHub cria uma VM efêmera.
2. O repositório é copiado para essa VM.
3. O workflow verifica que a configuração contém somente o endpoint Z.AI autorizado.
4. O secret é injetado pelo GitHub somente no job do Environment.
5. O smoke envia uma observação sintética ao modelo.
6. O retorno deve obedecer ao contrato `proposal_only`.
7. O job termina e o runner é descartado.

## Resultado aceito

`LIVE_PROVIDER_CONTRACT_PROVEN`

O resultado prova somente a camada cognitiva/protocolo do provider. Não prova integração com sistema real e não autoriza implantação.
