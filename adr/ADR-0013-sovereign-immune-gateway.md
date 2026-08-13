# ADR-0013 — Gateway Imune soberano e isolamento unilateral

**Estado:** aprovado e implementado em 13/08/2026.

## Decisão

Nenhum sistema protegido, aplicação externa, agente externo ou protocolo específico se conecta diretamente ao núcleo do Sistema Imunológico.

A única fronteira de integração é o **Immune Gateway**. O Gateway se adapta ao sistema protegido; o núcleo imune não se adapta ao sistema externo.

Fluxo estrutural:

`Sistema protegido ⇄ Adapter do Gateway ⇄ Immune Gateway ⇄ contratos imunes neutros ⇄ núcleo soberano`

## Autoridade assimétrica

A conexão não cria simetria de autoridade.

- sistema protegido pode fornecer somente telemetria, eventos, inventário, saúde e confirmações tratados como `UNTRUSTED_EXTERNAL_DATA`;
- sistema protegido não recebe identidade, token, escopo, memória, Provider Manager, Worker, PolicyGuard ou interface administrativa do núcleo;
- não existe endpoint externo de egress, shell, missão, política, memória, atualização ou execução;
- o Sistema Imunológico pode agir no sistema protegido somente pelo caminho interno de egress do Gateway;
- egress exige identidade interna `gateway:egress`, missão vinculada ao `system_id`, PolicyGuard e checkpoint quando houver mudança material;
- protocolos específicos pertencem a `immune_gateway.adapters`, nunca a `immune_core`;
- credenciais de peers/adapters permanecem fora do repositório e usam namespace `IMMUNE_GATEWAY_*`.

## Entrada externa

Push externo usa mensagem assinada com timestamp e nonce, com proteção contra replay e limite de tamanho/estrutura. Campos de controle fora do contrato de observação são rejeitados. Toda observação aceita recebe marca estrutural de dado externo não confiável antes de chegar à observabilidade/cognição.

## Saída para manutenção

O caminho de saída não é exposto pelo servidor HTTP do Gateway. Ele é uma capacidade interna do Sistema Imunológico, condicionada por identidade e política. O sistema protegido nunca pode invocar esse caminho de volta contra o núcleo.

## Migração WMCP2

O conhecimento de rede/protocolo de WMCP2 foi retirado de `immune_core/wmcp2_adapter.py` e movido para `immune_gateway.adapters.WMCP2GatewayAdapter`. O arquivo antigo permanece somente como marcador sem transporte ou execução, impedindo regressão para acoplamento direto.

## Doador Agentgateway

O projeto mantém Agentgateway como doador Open Source Apache-2.0 para transporte MCP/A2A, segurança e observabilidade. Ele pode fornecer peças por Adapter após laboratório, mas não substitui a fronteira soberana, PolicyGuard nem contratos imunes.
