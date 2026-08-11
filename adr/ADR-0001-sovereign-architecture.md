
# ADR-0001 — Arquitetura Soberana e Contratos Executáveis

**Status:** Accepted  
**Data:** 11/08/2026

## Contexto

O Sistema Imunológico precisa combinar IA, Workers e componentes OSS sem transferir
autoridade de missão, segurança, promoção, rollback ou aceite para componentes externos.

## Decisão

1. O núcleo soberano mantém autoridade e coordenação.
2. PolicyGuard é a fronteira obrigatória entre proposta e ação material.
3. Pensar, autorizar, executar e validar permanecem separados.
4. Contratos são JSON Schema versionados e estritos.
5. Estados de Mission e Incident seguem a especificação v1.0.
6. A máquina de Attempt é uma decisão de implementação desta ADR para operacionalizar a seção 9.3; a fonte não enumerou estados de Attempt.
7. Políticas normativas são expressas em Rego, com comportamento fail-closed onde autoridade é requerida.
8. Doadores são somente Open Source e entram por adapter após laboratório; nunca recebem soberania.
9. `MISSION_PROVEN` é um cálculo do Motor de Aceite baseado em evidência.
10. A implementação futura pode substituir motores OSS, mas não estes contratos soberanos sem ADR posterior e testes de compatibilidade.

## Consequências

- Dependências externas permanecem substituíveis.
- Falhas de política bloqueiam ação, em vez de permitir por omissão.
- Contratos podem ser validados antes da Fundação Soberana da Fase 2.
- Mudanças posteriores devem preservar compatibilidade ou declarar migração explícita.
