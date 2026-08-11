# ADR-0008 — Aprendizagem Controlada

**Status:** Accepted for Phase 8 proof

## Contexto

A Fase 8 deve transformar resultados comprovados em conhecimento reutilizável sem permitir que IA, Skill, log, documentação externa ou uma única observação se tornem verdade operacional por declaração.

## Decisão

1. Todo conhecimento novo nasce `QUARANTINED`.
2. O candidato só pode nascer de uma correção `ACCEPTED`, incidente `RESOLVED`, causa raiz confirmada e validação sem rollback.
3. A proveniência é derivada do estado soberano: incidente, hipótese raiz, tentativas, correção, validação e evidências SHA-256.
4. Confiança é calculada por resultados registrados, usando estimativa Beta simples `(sucessos + 1) / (sucessos + falhas + 2)`; o chamador não fornece o valor final.
5. Conhecimento `SYSTEM` exige ao menos um sucesso comprovado no sistema de origem e confiança mínima 0,60.
6. Conhecimento `GLOBAL` exige ao menos dois sucessos em sistemas distintos, mesma assinatura de remediação e confiança mínima 0,70.
7. Reprodução só conta quando outra correção aceita possui a mesma assinatura de remediação e validação comprovada.
8. Revisão e promoção são funções separadas: uma revisão `VALID` é obrigatória e o revisor não pode ser o promotor.
9. Uma regressão comprovada suspende conhecimento promovido imediatamente. Duas regressões registradas retiram o conhecimento automaticamente.
10. Evidência adulterada faz a revisão falhar fechada e suspende conhecimento já promovido.
11. Versões são imutáveis por linhagem. Versão nova só supersede versão promovida se não tiver confiança menor.
12. Skills continuam governadas pelo laboratório da Fase 4: aprendizagem não aprova Skill automaticamente nem altera `authority=adapter-only`/`executable=false`.
13. O motor não importa Provider Manager nem Cognitive Core e não expõe caminho de execução material. IA pode sugerir conteúdo, mas não pode registrar, revisar, promover ou retirar sem identidade e escopo soberanos.
14. Somente itens `PROMOTED` podem ser recuperados como conhecimento ativo; `SUSPENDED`, `RETIRED` e `SUPERSEDED` ficam fora do recall operacional.

## Consequências

- Aprendizagem é mais conservadora e exige evidência reproduzível.
- Conhecimento global custa mais prova do que conhecimento específico de um sistema.
- Regressões reduzem confiança e podem retirar automaticamente conhecimento antes que ele contamine novas decisões.
- A Fase 8 prova governança de conhecimento; ela não concede `MISSION_PROVEN` ao produto completo.
