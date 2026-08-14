# ADR-0014 — Validação isolada do Sistema Imunológico

**Data:** 2026-08-14
**Estado:** aprovado pelo responsável do produto

## Decisão

O Sistema Imunológico não será usado como alvo de teste em nenhum sistema, projeto ou runtime existente do responsável do produto.

Toda prova de construção e aceite deve ocorrer primeiro em ambiente descartável e isolado, usando Digital Twin, fixtures sintéticas, runners efêmeros e instâncias dedicadas de componentes necessários.

## Consequências obrigatórias

- Windows-MCP, WMCP2, Painel, SMART, API-ML, ADS-AI-HUB e demais sistemas existentes não são alvos de teste do Sistema Imunológico.
- Uma integração com TUNEL-CORE deve usar uma instância de laboratório dedicada e descartável, pinada a uma versão/commit, nunca o runtime TUNEL-CORE já em operação.
- Testes de IA ao vivo devem usar runner GitHub hospedado e o Environment `immune-live-test`.
- A chave do provedor de IA fica somente em secret do ambiente de teste e não entra em commit, `.env`, logs, fixtures ou evidências.
- O smoke de IA pode acessar somente o endpoint explicitamente permitido pelo contrato de teste.
- Nenhuma credencial ou endpoint de sistema protegido é disponibilizado ao runner.
- Nenhuma prova isolada autoriza implantação automática em sistemas reais.
- Qualquer futura aplicação em um sistema real exige autorização explícita e separada do responsável do produto.

## Arquitetura de prova

```text
GitHub Actions runner efêmero
        |
        +-- código do Immune-System
        +-- Digital Twin / fixtures sintéticas
        +-- TUNEL-CORE dedicado de laboratório, quando necessário
        +-- Secret de IA restrito ao Environment
        |
        +--> API Z.AI (somente smoke cognitivo)

SEM rota para sistemas existentes do responsável
```

## Critério de falha fechada

Se um teste isolado detectar referência a localhost, Windows-MCP, WMCP, TUNEL-CORE operacional ou outro alvo não autorizado na configuração específica do smoke de IA, o workflow deve falhar antes de usar a chave.
